package main

import (
	"context"
	"cyberguard.local/backend/internal/api"
	"cyberguard.local/backend/internal/auth"
	"cyberguard.local/backend/internal/config"
	"cyberguard.local/backend/internal/dbschema"
	"cyberguard.local/backend/internal/detection"
	"cyberguard.local/backend/internal/providers"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	if e := run(); e != nil {
		slog.Error("server stopped", "error", e.Error())
		os.Exit(1)
	}
}
func run() error {
	if err := config.LoadLocal(); err != nil {
		return err
	}
	if err := config.ValidateMasterKey(); err != nil {
		return err
	}
	if os.Getenv("DATABASE_URL") == "" {
		return fmt.Errorf("DATABASE_URL is required")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	db, e := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if e != nil {
		return fmt.Errorf("invalid database configuration")
	}
	defer db.Close()
	check, cancelCheck := context.WithTimeout(ctx, 5*time.Second)
	defer cancelCheck()
	if db.Ping(check) != nil {
		return fmt.Errorf("database connection failed; check DATABASE_URL and PostgreSQL service")
	}
	// Refuse to serve against a database whose migrations do not match this
	// build: every provider and analysis request would otherwise fail later
	// with an opaque server error.
	if err := dbschema.Check(check, db); err != nil {
		return fmt.Errorf("database schema check failed: %s", dbschema.Explain(err))
	}
	for _, name := range []string{"OPENAI_BASE_URL", "VIRUSTOTAL_BASE_URL"} {
		if err := config.ValidateBaseURL(name); err != nil {
			return err
		}
	}
	for _, id := range strings.Split(os.Getenv("TRUSTED_AUTHSERV_IDS"), ",") {
		if id = strings.TrimSpace(id); id != "" {
			detection.TrustedAuthServers = append(detection.TrustedAuthServers, id)
		}
	}
	origin := os.Getenv("APP_ORIGIN")
	if origin == "" {
		origin = "http://localhost:3000"
	}
	addr := os.Getenv("APP_ADDRESS")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	service := auth.New(db)
	service.Idle, e = config.Duration("SESSION_IDLE_TIMEOUT", 30*time.Minute)
	if e != nil {
		return e
	}
	service.Absolute, e = config.Duration("SESSION_ABSOLUTE_TIMEOUT", 12*time.Hour)
	if e != nil {
		return e
	}
	retention, e := config.RetentionDays()
	if e != nil {
		return e
	}
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				cleanup, cancel := context.WithTimeout(ctx, 30*time.Second)
				if retention > 0 {
					if _, err := db.Exec(cleanup, `DELETE FROM analyses WHERE created_at<$1`, time.Now().AddDate(0, 0, -retention)); err != nil {
						slog.Error("retention cleanup failed")
					}
				}
				if _, err := db.Exec(cleanup, `DELETE FROM sessions WHERE expires_at<now() OR last_seen_at<$1`, time.Now().Add(-service.Idle)); err != nil {
					slog.Error("session cleanup failed")
				}
				cancel()
			}
		}
	}()
	handler := (&api.Server{Auth: service, Origin: origin, Secure: os.Getenv("COOKIE_SECURE") == "true", PublicRegistration: os.Getenv("PUBLIC_REGISTRATION_ENABLED") == "true", ProviderSettings: providers.FromEnv(db), VirusTotalBaseURL: strings.TrimRight(os.Getenv("VIRUSTOTAL_BASE_URL"), "/")}).Router()
	// WriteTimeout must exceed the 170-second analysis budget enforced by the router.
	srv := &http.Server{Addr: addr, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 60 * time.Second, WriteTimeout: 185 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384}
	errs := make(chan error, 1)
	go func() {
		slog.Info("HTTP server listening", "address", addr, "origin", origin, "schema_version", dbschema.Required, "public_registration", os.Getenv("PUBLIC_REGISTRATION_ENABLED") == "true")
		errs <- srv.ListenAndServe()
	}()
	select {
	case e := <-errs:
		if e == http.ErrServerClosed {
			return nil
		}
		return e
	case <-ctx.Done():
		shutdown, c := context.WithTimeout(context.Background(), 10*time.Second)
		defer c()
		return srv.Shutdown(shutdown)
	}
}
