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
	"strconv"
	"strings"
	"time"
	"unicode"
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
	// Provider defaults to openai for backwards compatibility with existing callers.
	Provider                   string
	ClientFactory              func(string, string) *ai.Client
	DB                         *pgxpool.Pool
	Master                     []byte
	FallbackKey, FallbackModel string
	FallbackEnabled            bool
	// OpenAIBaseURL overrides https://api.openai.com/v1 (operator setting for
	// gateways and mocked end-to-end tests). Never taken from user input.
	OpenAIBaseURL string
	// Client-side VirusTotal guard. Defaults follow the Public API allowance.
	LookupsPerMinute, LookupsPerDay int
}

func (s *Service) name() string {
	if s.Provider == "" {
		return "openai"
	}
	return s.Provider
}

// For returns a copy sharing persistence and encryption, scoped to one provider.
func (s *Service) For(provider string) *Service {
	c := *s
	c.Provider = provider
	if provider != "openai" {
		c.FallbackEnabled = false
	}
	return &c
}

func FromEnv(db *pgxpool.Pool) *Service {
	k, _ := base64.StdEncoding.DecodeString(os.Getenv("PROVIDER_MASTER_KEY"))
	s := &Service{DB: db, Master: k, FallbackKey: os.Getenv("OPENAI_API_KEY"), FallbackModel: os.Getenv("OPENAI_MODEL"), FallbackEnabled: os.Getenv("OPENAI_OPERATOR_FALLBACK_ENABLED") == "true", OpenAIBaseURL: strings.TrimRight(os.Getenv("OPENAI_BASE_URL"), "/")}
	s.LookupsPerMinute, _ = strconv.Atoi(os.Getenv("VIRUSTOTAL_REQUESTS_PER_MINUTE"))
	s.LookupsPerDay, _ = strconv.Atoi(os.Getenv("VIRUSTOTAL_REQUESTS_PER_DAY"))
	return s
}

// NormalizeKey removes the whitespace that copy/paste adds around a secret and
// rejects values that cannot be sent as an HTTP header (the previous code
// stored them and later reported a misleading network failure).
func NormalizeKey(key string) (string, error) {
	key = strings.TrimSpace(key)
	if len(key) > 4096 {
		return "", errors.New("INVALID_PROVIDER_SETTINGS")
	}
	for _, r := range key {
		if r > unicode.MaxASCII || unicode.IsSpace(r) || unicode.IsControl(r) {
			return "", errors.New("PROVIDER_KEY_MALFORMED")
		}
	}
	return key, nil
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
	return a.Seal(nonce, nonce, []byte(key), []byte("provider:v1:"+s.name()+":"+owner)), nil
}
func (s *Service) Open(owner string, b []byte) (string, error) {
	a, e := s.crypt()
	if e != nil {
		return "", e
	}
	if len(b) < a.NonceSize() {
		return "", errors.New("PROVIDER_CREDENTIAL_INVALID")
	}
	p, e := a.Open(nil, b[:a.NonceSize()], b[a.NonceSize():], []byte("provider:v1:"+s.name()+":"+owner))
	if e != nil {
		return "", errors.New("PROVIDER_CREDENTIAL_INVALID")
	}
	return string(p), nil
}
func (s *Service) Read(ctx context.Context, owner string) (Config, []byte, error) {
	c := Config{Provider: s.name(), Status: "not_configured", Source: "user"}
	var secret []byte
	e := s.DB.QueryRow(ctx, `SELECT provider,model,enabled,credential,connection_status,last_success_at,revision FROM provider_settings WHERE user_id=$1 AND provider=$2`, owner, s.name()).Scan(&c.Provider, &c.Model, &c.Enabled, &secret, &c.Status, &c.LastSuccess, &c.Revision)
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
	if provider != s.name() || (provider != "openai" && provider != "virustotal") {
		return errors.New("PROVIDER_UNSUPPORTED")
	}
	model = strings.TrimSpace(model)
	if provider == "openai" && !modelPattern.MatchString(model) {
		return errors.New("PROVIDER_MODEL_INVALID")
	}
	if provider != "openai" {
		model = ""
	}
	key, e := NormalizeKey(key)
	if e != nil {
		return e
	}
	if _, e = s.crypt(); e != nil {
		// Fail before touching the database, even when no new key is supplied.
		return e
	}
	if key == "" {
		// A first save without a key would create an unusable "enabled" row.
		var exists bool
		if e = s.DB.QueryRow(ctx, `SELECT credential IS NOT NULL FROM provider_settings WHERE user_id=$1 AND provider=$2`, owner, provider).Scan(&exists); e != nil && !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		if !exists {
			return errors.New("PROVIDER_KEY_REQUIRED")
		}
	}
	var encrypted []byte
	if key != "" {
		encrypted, e = s.Seal(owner, key)
		if e != nil {
			return e
		}
	}
	_, e = s.DB.Exec(ctx, `INSERT INTO provider_settings(user_id,provider,model,credential,enabled,revision) VALUES($1,$6,$2,$3,$4,$5) ON CONFLICT(user_id,provider) DO UPDATE SET model=excluded.model,credential=COALESCE(excluded.credential,provider_settings.credential),enabled=excluded.enabled,revision=excluded.revision,connection_status='untested',last_success_at=NULL,updated_at=now()`, owner, model, encrypted, enabled, uuid.NewString(), provider)
	return e
}
func (s *Service) Remove(ctx context.Context, owner string) error {
	_, e := s.DB.Exec(ctx, `INSERT INTO provider_settings(user_id,provider,model,enabled,revision,connection_status) VALUES($1,$3,'',false,$2,'not_configured') ON CONFLICT(user_id,provider) DO UPDATE SET credential=NULL,enabled=false,connection_status='not_configured',last_success_at=NULL,revision=excluded.revision,updated_at=now()`, owner, uuid.NewString(), s.name())
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
	if s.ClientFactory != nil {
		return c, s.ClientFactory(key, c.Model), nil
	}
	return c, &ai.Client{Key: key, Model: c.Model, BaseURL: s.OpenAIBaseURL}, nil
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
	_, e := s.DB.Exec(ctx, `UPDATE provider_settings SET connection_status=$3,last_success_at=COALESCE($4,last_success_at) WHERE user_id=$1 AND revision=$2 AND provider=$5`, owner, c.Revision, status, success, s.name())
	return e
}

// Limits returns the effective client-side VirusTotal request allowance.
func (s *Service) Limits() (perMinute, perDay int) {
	perMinute, perDay = s.LookupsPerMinute, s.LookupsPerDay
	if perMinute < 1 || perMinute > 1000 {
		perMinute = 4
	}
	if perDay < 1 || perDay > 1000000 {
		perDay = 500
	}
	return
}

// ReserveLookup atomically reserves one VirusTotal request for the owner. It
// enforces a true sliding 60-second window plus a UTC daily allowance across
// server processes. Replacing or deleting a credential never resets counters.
// The limit protects the user's quota; VirusTotal still enforces its own.
func (s *Service) ReserveLookup(ctx context.Context, owner string) (bool, error) {
	perMinute, perDay := s.Limits()
	tag, err := s.DB.Exec(ctx, `UPDATE provider_settings SET
 lookup_recent=array_append(ARRAY(SELECT t FROM unnest(lookup_recent) t WHERE t>now()-interval '60 seconds'),now()),
 next_lookup_at=NULL,
 lookup_count=CASE WHEN lookup_day=(now() AT TIME ZONE 'UTC')::date THEN lookup_count+1 ELSE 1 END,
 lookup_day=(now() AT TIME ZONE 'UTC')::date
 WHERE user_id=$1 AND provider='virustotal' AND credential IS NOT NULL
 AND (SELECT count(*) FROM unnest(lookup_recent) t WHERE t>now()-interval '60 seconds')<$2
 AND (lookup_day IS DISTINCT FROM (now() AT TIME ZONE 'UTC')::date OR lookup_count<$3)`, owner, perMinute, perDay)
	return tag.RowsAffected() == 1, err
}
