package providers

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"cyberguard.local/backend/internal/detection"
	ai "cyberguard.local/backend/internal/openai"
	"encoding/base64"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"regexp"
	"time"
)

type Adapter interface {
	Assess(context.Context, detection.Report) (ai.Assessment, error)
}
type Config struct {
	Provider      string     `json:"provider"`
	Model         string     `json:"model"`
	Enabled       bool       `json:"enabled"`
	HasCredential bool       `json:"has_credential"`
	Status        string     `json:"connection_status"`
	LastSuccess   *time.Time `json:"last_success_at"`
	Source        string     `json:"source"`
	Revision      string     `json:"-"`
}
type Service struct {
	ClientFactory func(string,string)*ai.Client
	DB                         *pgxpool.Pool
	Master                     []byte
	FallbackKey, FallbackModel string
	FallbackEnabled            bool
}

func FromEnv(db *pgxpool.Pool) *Service {
	k, _ := base64.StdEncoding.DecodeString(os.Getenv("PROVIDER_MASTER_KEY"))
	return &Service{DB: db, Master: k, FallbackKey: os.Getenv("OPENAI_API_KEY"), FallbackModel: os.Getenv("OPENAI_MODEL"), FallbackEnabled: os.Getenv("OPENAI_OPERATOR_FALLBACK_ENABLED") == "true"}
}
func (s *Service) crypt() (cipher.AEAD, error) {
	if len(s.Master) != 32 {
		return nil, errors.New("PROVIDER_ENCRYPTION_UNAVAILABLE")
	}
	b, e := aes.NewCipher(s.Master)
	if e != nil {
		return nil, e
	}
	return cipher.NewGCM(b)
}
func (s *Service) Seal(owner, key string) ([]byte, error) {
	a, e := s.crypt()
	if e != nil {
		return nil, e
	}
	nonce := make([]byte, a.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return nil, e
	}
	return a.Seal(nonce, nonce, []byte(key), []byte("provider:v1:openai:"+owner)), nil
}
func (s *Service) Open(owner string, b []byte) (string, error) {
	a, e := s.crypt()
	if e != nil {
		return "", e
	}
	if len(b) < a.NonceSize() {
		return "", errors.New("PROVIDER_CREDENTIAL_INVALID")
	}
	p, e := a.Open(nil, b[:a.NonceSize()], b[a.NonceSize():], []byte("provider:v1:openai:"+owner))
	if e != nil {
		return "", errors.New("PROVIDER_CREDENTIAL_INVALID")
	}
	return string(p), nil
}
func (s *Service) Read(ctx context.Context, owner string) (Config, []byte, error) {
	c := Config{Provider: "openai", Status: "not_configured", Source: "user"}
	var secret []byte
	e := s.DB.QueryRow(ctx, `SELECT provider,model,enabled,credential,connection_status,last_success_at,revision FROM provider_settings WHERE user_id=$1`, owner).Scan(&c.Provider, &c.Model, &c.Enabled, &secret, &c.Status, &c.LastSuccess, &c.Revision)
	if errors.Is(e, pgx.ErrNoRows) {
		if s.FallbackEnabled && s.FallbackKey != "" && s.FallbackModel != "" {
			c.Model = s.FallbackModel
			c.Enabled = true
			c.HasCredential = true
			c.Source = "operator"
			c.Status = "untested"
		}
		return c, nil, nil
	}
	c.HasCredential = len(secret) > 0
	return c, secret, e
}

var modelPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$`)

func (s *Service) Save(ctx context.Context, owner, provider, model, key string, enabled bool) error {
	if provider != "openai" {
		return errors.New("PROVIDER_UNSUPPORTED")
	}
	if !modelPattern.MatchString(model) || len(key) > 4096 {
		return errors.New("INVALID_PROVIDER_SETTINGS")
	}
	var encrypted []byte
	var e error
	if key != "" {
		encrypted, e = s.Seal(owner, key)
		if e != nil {
			return e
		}
	}
	_, e = s.DB.Exec(ctx, `INSERT INTO provider_settings(user_id,provider,model,credential,enabled,revision) VALUES($1,'openai',$2,$3,$4,$5) ON CONFLICT(user_id) DO UPDATE SET model=excluded.model,credential=COALESCE(excluded.credential,provider_settings.credential),enabled=excluded.enabled,revision=excluded.revision,connection_status='untested',last_success_at=NULL,updated_at=now()`, owner, model, encrypted, enabled, uuid.NewString())
	return e
}
func (s *Service) Remove(ctx context.Context, owner string) error {
	_, e := s.DB.Exec(ctx, `INSERT INTO provider_settings(user_id,provider,model,enabled,revision) VALUES($1,'openai','',false,$2) ON CONFLICT(user_id) DO UPDATE SET credential=NULL,enabled=false,connection_status='not_configured',last_success_at=NULL,revision=excluded.revision,updated_at=now()`, owner, uuid.NewString())
	return e
}
func (s *Service) Resolve(ctx context.Context, owner string) (Config, *ai.Client, error) {
	c, b, e := s.Read(ctx, owner)
	if e != nil {
		return c, nil, e
	}
	if !c.Enabled || !c.HasCredential {
		return c, nil, errors.New("PROVIDER_NOT_CONFIGURED")
	}
	key := s.FallbackKey
	if c.Source == "user" {
		key, e = s.Open(owner, b)
		if e != nil {
			return c, nil, e
		}
	}
	if s.ClientFactory!=nil{return c,s.ClientFactory(key,c.Model),nil}
	return c, &ai.Client{Key: key, Model: c.Model}, nil
}
func (s *Service) Tested(ctx context.Context, owner string, c Config, code string) error {
	status := "credential_validated"
	var success *time.Time
	if code != "" {
		status = code
	} else {
		now := time.Now().UTC()
		success = &now
	}
	_, e := s.DB.Exec(ctx, `UPDATE provider_settings SET connection_status=$3,last_success_at=COALESCE($4,last_success_at) WHERE user_id=$1 AND revision=$2`, owner, c.Revision, status, success)
	return e
}
