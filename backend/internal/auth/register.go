package auth

import (
	"context"
	"cyberguard.local/backend/internal/passwords"
	"errors"
	"github.com/google/uuid"
	"strings"
	"unicode"
	"unicode/utf8"
)

var ErrRegistrationInput = errors.New("INVALID_REGISTRATION_INPUT")

// Register deliberately returns the same result for an existing email. It never
// changes existing accounts, passwords, temporary credentials, or sessions.
func (s *Service) Register(ctx context.Context, email, name, password, confirmation string) error {
	email, err := Email(email)
	if err != nil {
		return ErrRegistrationInput
	}
	name = strings.TrimSpace(name)
	if !utf8.ValidString(name) || len(name) == 0 || len(name) > 200 || strings.IndexFunc(name, unicode.IsControl) >= 0 {
		return ErrRegistrationInput
	}
	if password != confirmation || passwords.Validate(password) != nil {
		return ErrRegistrationInput
	}
	hash, err := passwords.Hash(password)
	if err != nil {
		return err
	}
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	id := uuid.NewString()
	tag, err := tx.Exec(ctx, `INSERT INTO users(id,email,display_name,password_hash,account_status,must_change_password,password_changed_at) VALUES($1,$2,$3,$4,'active',false,now()) ON CONFLICT (email) DO NOTHING`, id, email, name, hash)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 1 {
		if err = event(ctx, tx, id, "PUBLIC_REGISTRATION"); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
