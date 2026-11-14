package auth

import (
	"context"
	"crypto/sha256"
	"cyberguard.local/backend/internal/passwords"
	"encoding/base64"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"net/mail"
	"strings"
	"time"
)

var ErrCredentials = errors.New("INVALID_CREDENTIALS")
var ErrSession = errors.New("UNAUTHENTICATED")

type User struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"display_name"`
}
type Session struct {
	User  User   `json:"user"`
	Setup bool   `json:"password_change_required"`
	CSRF  string `json:"csrf_token"`
	Token string `json:"-"`
	Kind  string `json:"-"`
}
type Service struct {
	DB             *pgxpool.Pool
	Idle, Absolute time.Duration
	dummy          string
}

func New(db *pgxpool.Pool) *Service {
	h, _ := passwords.Hash(passwords.Token())
	return &Service{DB: db, Idle: 30 * time.Minute, Absolute: 12 * time.Hour, dummy: h}
}
func digest(s string) []byte { h := sha256.Sum256([]byte(s)); return h[:] }
func csrfToken(token string) string {
	return base64.RawURLEncoding.EncodeToString(digest("cyberguard-csrf:" + token))
}
func Email(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	a, e := mail.ParseAddress(s)
	if e != nil || a.Address != s || len(s) > 254 {
		return "", errors.New("invalid email")
	}
	return s, nil
}
func (s *Service) Provision(ctx context.Context, email, name, action string) (string, error) {
	email, e := Email(email)
	if e != nil {
		return "", e
	}
	if action == "create" && (strings.TrimSpace(name) == "" || len(name) > 200) {
		return "", errors.New("invalid name")
	}
	token := passwords.Token()
	h, e := passwords.Hash(token)
	if e != nil {
		return "", e
	}
	tx, e := s.DB.Begin(ctx)
	if e != nil {
		return "", e
	}
	defer tx.Rollback(ctx)
	var id string
	if action == "create" {
		id = uuid.NewString()
		_, e = tx.Exec(ctx, `INSERT INTO users(id,email,display_name,account_status,temporary_password_hash,temporary_password_expires_at) VALUES($1,$2,$3,'pending_activation',$4,now()+interval '24 hours')`, id, email, name, h)
	} else {
		e = tx.QueryRow(ctx, `SELECT id FROM users WHERE email=$1 FOR UPDATE`, email).Scan(&id)
		if e == nil {
			if action == "disable" {
				_, e = tx.Exec(ctx, `UPDATE users SET account_status='disabled',temporary_password_hash=NULL,updated_at=now() WHERE id=$1`, id)
				token = ""
			} else if action == "reset-password" {
				_, e = tx.Exec(ctx, `UPDATE users SET account_status='pending_activation',must_change_password=true,password_hash=NULL,temporary_password_hash=$2,temporary_password_expires_at=now()+interval '24 hours',temporary_password_used_at=NULL,updated_at=now() WHERE id=$1`, id, h)
			} else {
				return "", errors.New("invalid operation")
			}
		}
	}
	if e != nil {
		return "", e
	}
	if _, e = tx.Exec(ctx, `DELETE FROM sessions WHERE user_id=$1`, id); e != nil {
		return "", e
	}
	if e = event(ctx, tx, id, "USER_"+action); e != nil {
		return "", e
	}
	return token, tx.Commit(ctx)
}
func event(ctx context.Context, tx pgx.Tx, id, code string) error {
	_, e := tx.Exec(ctx, `INSERT INTO auth_security_events(id,user_id,event_code) VALUES($1,$2,$3)`, uuid.NewString(), id, code)
	return e
}
func (s *Service) issue(ctx context.Context, tx pgx.Tx, u User, setup bool) (Session, error) {
	v := Session{User: u, Setup: setup, Token: passwords.Token(), CSRF: passwords.Token(), Kind: "regular"}
	v.CSRF = csrfToken(v.Token)
	ttl := s.Absolute
	if setup {
		v.Kind = "setup"
		ttl = 15 * time.Minute
	}
	_, e := tx.Exec(ctx, `INSERT INTO sessions(token_hash,user_id,csrf_hash,kind,expires_at) VALUES($1,$2,$3,$4,$5)`, digest(v.Token), u.ID, digest(v.CSRF), v.Kind, time.Now().Add(ttl))
	return v, e
}
func (s *Service) Login(ctx context.Context, email, pw string) (Session, error) {
	var out Session
	email, _ = Email(email)
	tx, e := s.DB.Begin(ctx)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	var u User
	var status string
	var hash, tmp *string
	var expires, used *time.Time
	var setup bool
	e = tx.QueryRow(ctx, `SELECT id,email,display_name,account_status,password_hash,temporary_password_hash,temporary_password_expires_at,temporary_password_used_at,must_change_password FROM users WHERE email=$1 FOR UPDATE`, email).Scan(&u.ID, &u.Email, &u.Name, &status, &hash, &tmp, &expires, &used, &setup)
	if e != nil {
		passwords.Verify(s.dummy, pw)
		if errors.Is(e, pgx.ErrNoRows) {
			return out, ErrCredentials
		}
		return out, e
	}
	candidate := s.dummy
	if setup && tmp != nil {
		candidate = *tmp
	} else if hash != nil {
		candidate = *hash
	}
	valid := passwords.Verify(candidate, pw)
	if !valid || status == "disabled" || (setup && (expires == nil || time.Now().After(*expires) || used != nil)) {
		return out, ErrCredentials
	}
	if setup {
		_, e = tx.Exec(ctx, `UPDATE users SET temporary_password_used_at=now(),temporary_password_hash=NULL WHERE id=$1`, u.ID)
		if e != nil {
			return out, e
		}
	}
	out, e = s.issue(ctx, tx, u, setup)
	if e != nil {
		return out, e
	}
	_, e = tx.Exec(ctx, `UPDATE users SET last_login_at=now() WHERE id=$1`, u.ID)
	if e != nil {
		return out, e
	}
	if e = event(ctx, tx, u.ID, "LOGIN"); e != nil {
		return out, e
	}
	return out, tx.Commit(ctx)
}
func (s *Service) Resolve(ctx context.Context, token string) (Session, error) {
	var v Session
	v.Token = token
	v.CSRF = csrfToken(token)
	e := s.DB.QueryRow(ctx, `UPDATE sessions s SET last_seen_at=now() FROM users u WHERE s.user_id=u.id AND s.token_hash=$1 AND s.expires_at>now() AND s.last_seen_at>$2 AND u.account_status<>'disabled' RETURNING u.id,u.email,u.display_name,s.kind`, digest(token), time.Now().Add(-s.Idle)).Scan(&v.User.ID, &v.User.Email, &v.User.Name, &v.Kind)
	v.Setup = v.Kind == "setup"
	if errors.Is(e, pgx.ErrNoRows) {
		e = ErrSession
	}
	return v, e
}
func (s *Service) CSRF(ctx context.Context, token, csrf string) bool {
	var ok bool
	e := s.DB.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM sessions WHERE token_hash=$1 AND csrf_hash=$2 AND expires_at>now())`, digest(token), digest(csrf)).Scan(&ok)
	return e == nil && ok
}
func (s *Service) Logout(ctx context.Context, token string) error {
	_, e := s.DB.Exec(ctx, `DELETE FROM sessions WHERE token_hash=$1`, digest(token))
	return e
}
func (s *Service) Password(ctx context.Context, v Session, current, next string, activate bool) (Session, error) {
	var out Session
	if e := passwords.Validate(next); e != nil {
		return out, e
	}
	h, e := passwords.Hash(next)
	if e != nil {
		return out, e
	}
	tx, e := s.DB.Begin(ctx)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	var old *string
	var status string
	e = tx.QueryRow(ctx, `SELECT password_hash,account_status FROM users WHERE id=$1 FOR UPDATE`, v.User.ID).Scan(&old, &status)
	if e != nil {
		return out, e
	}
	var kind string
	e = tx.QueryRow(ctx, `SELECT kind FROM sessions WHERE token_hash=$1 AND user_id=$2 AND expires_at>now() AND last_seen_at>$3 FOR UPDATE`, digest(v.Token), v.User.ID, time.Now().Add(-s.Idle)).Scan(&kind)
	if e != nil || status == "disabled" {
		return out, ErrSession
	}
	if activate {
		if kind != "setup" || status != "pending_activation" {
			return out, ErrSession
		}
	} else if kind != "regular" || old == nil || !passwords.Verify(*old, current) {
		return out, ErrCredentials
	}
	_, e = tx.Exec(ctx, `UPDATE users SET password_hash=$2,account_status='active',must_change_password=false,temporary_password_hash=NULL,temporary_password_expires_at=NULL,password_changed_at=now(),updated_at=now() WHERE id=$1`, v.User.ID, h)
	if e != nil {
		return out, e
	}
	_, e = tx.Exec(ctx, `DELETE FROM sessions WHERE user_id=$1`, v.User.ID)
	if e != nil {
		return out, e
	}
	if activate {
		out, e = s.issue(ctx, tx, v.User, false)
		if e != nil {
			return out, e
		}
	}
	if e = event(ctx, tx, v.User.ID, "PASSWORD_CHANGED"); e != nil {
		return out, e
	}
	return out, tx.Commit(ctx)
}
