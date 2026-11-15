package main

import (
	"context"
	"cyberguard.local/backend/internal/auth"
	"cyberguard.local/backend/internal/config"
	"cyberguard.local/backend/internal/dbschema"
	"flag"
	"fmt"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"strings"
	"time"
)

func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, "Operation failed:", e)
		os.Exit(1)
	}
}
func run() error {
	if err := config.LoadLocal(); err != nil {
		return err
	}
	if len(os.Args) < 2 {
		return fmt.Errorf("usage: cyberguardctl migrate | status | users create|reset-password|disable --email EMAIL [--name NAME]")
	}
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return fmt.Errorf("DATABASE_URL is required")
	}
	if os.Args[1] == "status" {
		// Read-only check used by the setup and start scripts.
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		db, e := pgxpool.New(ctx, dsn)
		if e != nil {
			return fmt.Errorf("DATABASE_URL is not a valid PostgreSQL connection string")
		}
		defer db.Close()
		if db.Ping(ctx) != nil {
			return fmt.Errorf("cannot connect to PostgreSQL; check that the service is running and that DATABASE_URL has the right host, port, database, user and password")
		}
		version, dirty, e := dbschema.Version(ctx, db)
		if e == nil {
			e = dbschema.Evaluate(version, dirty)
		}
		if e != nil {
			return fmt.Errorf("%s", dbschema.Explain(e))
		}
		fmt.Println("Database reachable; schema version", version, "matches this application.")
		return nil
	}
	if os.Args[1] == "migrate" {
		path := os.Getenv("MIGRATIONS_PATH")
		if path == "" {
			path = "../migrations"
		}
		dsn = strings.Replace(dsn, "postgres://", "pgx5://", 1)
		dsn = strings.Replace(dsn, "postgresql://", "pgx5://", 1)
		m, e := migrate.New("file://"+path, dsn)
		if e != nil {
			return fmt.Errorf("migration initialization failed; check DATABASE_URL, that PostgreSQL is running and that MIGRATIONS_PATH (%s) exists", path)
		}
		defer m.Close()
		e = m.Up()
		if e != nil && e != migrate.ErrNoChange {
			return fmt.Errorf("migration failed: %v", e)
		}
		version, _, _ := m.Version()
		fmt.Println("Database schema is at version", version, "- required:", dbschema.Required)
		if int(version) != dbschema.Required {
			return fmt.Errorf("schema version %d does not match required version %d; application files and migrations are out of sync", version, dbschema.Required)
		}
		return nil
	}
	if len(os.Args) < 3 || os.Args[1] != "users" {
		return fmt.Errorf("invalid command")
	}
	action := os.Args[2]
	if action != "create" && action != "reset-password" && action != "disable" {
		return fmt.Errorf("invalid operation")
	}
	f := flag.NewFlagSet("users", flag.ContinueOnError)
	email := f.String("email", "", "account email")
	name := f.String("name", "", "display name")
	if e := f.Parse(os.Args[3:]); e != nil {
		return e
	}
	if action != "disable" {
		st, e := os.Stdout.Stat()
		if e != nil || st.Mode()&os.ModeCharDevice == 0 {
			return fmt.Errorf("temporary credentials must be displayed in an interactive terminal")
		}
	}
	ctx, c := context.WithTimeout(context.Background(), 30*time.Second)
	defer c()
	db, e := pgxpool.New(ctx, dsn)
	if e != nil {
		return fmt.Errorf("database configuration invalid")
	}
	defer db.Close()
	token, e := auth.New(db).Provision(ctx, *email, *name, action)
	if e != nil {
		return fmt.Errorf("account operation failed")
	}
	if token != "" {
		fmt.Println("Temporary password (expires in 24 hours):", token)
	} else {
		fmt.Println("Account disabled")
	}
	return nil
}
