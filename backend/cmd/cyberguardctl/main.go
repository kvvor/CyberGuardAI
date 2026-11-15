package main

import (
	"context"
	"cyberguard.local/backend/internal/auth"
	"cyberguard.local/backend/internal/config"
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
		return fmt.Errorf("usage: cyberguardctl migrate | users create|reset-password|disable --email EMAIL [--name NAME]")
	}
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		return fmt.Errorf("DATABASE_URL is required")
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
			return fmt.Errorf("migration initialization failed")
		}
		defer m.Close()
		e = m.Up()
		if e == migrate.ErrNoChange {
			return nil
		}
		return e
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
