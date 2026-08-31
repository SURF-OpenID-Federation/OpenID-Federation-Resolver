package apitokens

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	PATPrefix             = "oidf_pat_"
	ScopeAPIFull          = "api:full"
	defaultPATTTLDays     = 90
	defaultPATMaxTTLDays  = 365
	defaultUnusedWarnDays = 60
	patSecretEntropyBytes = 24
	lastUsedThrottle      = time.Minute
)

var (
	ErrTokenNotFound = errors.New("token not found")
	ErrTokenRevoked  = errors.New("token revoked")
	ErrTokenExpired  = errors.New("token expired")
	ErrInvalidToken  = errors.New("invalid token")
	ErrInvalidTTL    = errors.New("invalid token ttl")
)

// Store persists PAT hashes under DATA_PATH.
type Store struct {
	mu     sync.Mutex
	path   string
	pepper []byte
	data   tokensFile
}

type tokensFile struct {
	Version int         `json:"version"`
	Tokens  []PATRecord `json:"tokens"`
}

// PATRecord is metadata + hash (never plaintext).
type PATRecord struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	SecretHash string     `json:"secret_hash"`
	HashAlg    string     `json:"hash_alg"`
	Scopes     []string   `json:"scopes"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	RevokedAt  *time.Time `json:"revoked_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
}

// PATPublic is the secret-free view.
type PATPublic struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	Scopes     []string   `json:"scopes"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	Status     string     `json:"status"`
	UnusedWarn bool       `json:"unused_warn"`
}

var (
	globalMu    sync.RWMutex
	globalStore *Store
)

// Init opens or creates the token store.
func Init(dataPath string) (*Store, error) {
	path := strings.TrimSpace(os.Getenv("API_PAT_STORE_PATH"))
	if path == "" {
		if dataPath == "" {
			dataPath = "./data"
		}
		path = filepath.Join(dataPath, "api_tokens.json")
	}
	pepper, err := loadOrCreatePepper(dataPath)
	if err != nil {
		return nil, err
	}
	s := &Store{path: path, pepper: pepper}
	if err := s.load(); err != nil {
		return nil, err
	}
	globalMu.Lock()
	globalStore = s
	globalMu.Unlock()
	return s, nil
}

// Get returns the process-global store (nil if not initialized).
func Get() *Store {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return globalStore
}

// SetForTest replaces the process-global store. Pass nil to clear.
func SetForTest(s *Store) {
	globalMu.Lock()
	globalStore = s
	globalMu.Unlock()
}

func loadOrCreatePepper(dataPath string) ([]byte, error) {
	if env := strings.TrimSpace(os.Getenv("API_PAT_PEPPER")); env != "" {
		return []byte(env), nil
	}
	if err := os.MkdirAll(dataPath, 0o750); err != nil {
		return nil, fmt.Errorf("api tokens: create data path: %w", err)
	}
	pepperPath := filepath.Join(dataPath, ".api_pat_pepper")
	if b, err := os.ReadFile(pepperPath); err == nil {
		b = []byte(strings.TrimSpace(string(b)))
		if len(b) > 0 {
			return b, nil
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("api tokens: read pepper: %w", err)
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	encoded := hex.EncodeToString(raw)
	if err := os.WriteFile(pepperPath, []byte(encoded+"\n"), 0o600); err != nil {
		return nil, fmt.Errorf("api tokens: write pepper: %w", err)
	}
	return []byte(encoded), nil
}

func (s *Store) load() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			s.data = tokensFile{Version: 1, Tokens: []PATRecord{}}
			return nil
		}
		return fmt.Errorf("api tokens: read: %w", err)
	}
	var file tokensFile
	if err := json.Unmarshal(data, &file); err != nil {
		return fmt.Errorf("api tokens: parse: %w", err)
	}
	if file.Tokens == nil {
		file.Tokens = []PATRecord{}
	}
	if file.Version == 0 {
		file.Version = 1
	}
	s.data = file
	return nil
}

func (s *Store) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		return err
	}
	s.data.Version = 1
	raw, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *Store) hashSecret(secret string) string {
	mac := hmac.New(sha256.New, s.pepper)
	_, _ = mac.Write([]byte(secret))
	return hex.EncodeToString(mac.Sum(nil))
}

func hashEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// CreatePAT mints a token. Plaintext is returned once.
func (s *Store) CreatePAT(name string, ttl time.Duration, now time.Time) (plaintext string, pub PATPublic, err error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", PATPublic{}, fmt.Errorf("name is required")
	}
	if ttl <= 0 {
		ttl = time.Duration(DefaultTTLDays()) * 24 * time.Hour
	}
	maxTTL := time.Duration(MaxTTLDays()) * 24 * time.Hour
	if ttl > maxTTL {
		return "", PATPublic{}, fmt.Errorf("%w: max %d days", ErrInvalidTTL, MaxTTLDays())
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	id := "tok_" + randomString(16)
	shortID := randomString(8)
	secret := randomHex(patSecretEntropyBytes)
	plaintext = PATPrefix + shortID + "_" + secret
	rec := PATRecord{
		ID:         id,
		Name:       name,
		Prefix:     PATPrefix + shortID,
		SecretHash: s.hashSecret(plaintext),
		HashAlg:    "hmac-sha256",
		Scopes:     []string{ScopeAPIFull},
		CreatedAt:  now.UTC(),
		ExpiresAt:  now.UTC().Add(ttl),
	}
	s.data.Tokens = append(s.data.Tokens, rec)
	if err := s.saveLocked(); err != nil {
		return "", PATPublic{}, err
	}
	log.Printf("audit pat_created id=%s prefix=%s name=%q expires_at=%s", id, rec.Prefix, name, rec.ExpiresAt.Format(time.RFC3339))
	return plaintext, toPublic(rec, now), nil
}

// ListPATs returns secret-free metadata.
func (s *Store) ListPATs(now time.Time) []PATPublic {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]PATPublic, 0, len(s.data.Tokens))
	for _, t := range s.data.Tokens {
		out = append(out, toPublic(t, now))
	}
	return out
}

// GetPAT returns one token by id.
func (s *Store) GetPAT(id string, now time.Time) (PATPublic, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.data.Tokens {
		if t.ID == id {
			return toPublic(t, now), nil
		}
	}
	return PATPublic{}, ErrTokenNotFound
}

// RevokePAT soft-deletes a token.
func (s *Store) RevokePAT(id string, now time.Time) (PATPublic, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.data.Tokens {
		if s.data.Tokens[i].ID != id {
			continue
		}
		if s.data.Tokens[i].RevokedAt == nil {
			t := now.UTC()
			s.data.Tokens[i].RevokedAt = &t
			if err := s.saveLocked(); err != nil {
				return PATPublic{}, err
			}
			log.Printf("audit pat_revoked id=%s prefix=%s", id, s.data.Tokens[i].Prefix)
		}
		return toPublic(s.data.Tokens[i], now), nil
	}
	return PATPublic{}, ErrTokenNotFound
}

// Authenticate verifies a PAT secret.
func (s *Store) Authenticate(secret string, now time.Time) error {
	secret = strings.TrimSpace(secret)
	if secret == "" || !strings.HasPrefix(secret, PATPrefix) {
		return ErrInvalidToken
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	want := s.hashSecret(secret)
	for i := range s.data.Tokens {
		t := &s.data.Tokens[i]
		if !hashEqual(t.SecretHash, want) {
			continue
		}
		if t.RevokedAt != nil {
			return ErrTokenRevoked
		}
		if !now.Before(t.ExpiresAt) {
			return ErrTokenExpired
		}
		if t.LastUsedAt == nil || now.Sub(*t.LastUsedAt) >= lastUsedThrottle {
			ts := now.UTC()
			t.LastUsedAt = &ts
			_ = s.saveLocked()
		}
		return nil
	}
	return ErrInvalidToken
}

func toPublic(t PATRecord, now time.Time) PATPublic {
	status := "active"
	if t.RevokedAt != nil {
		status = "revoked"
	} else if !now.Before(t.ExpiresAt) {
		status = "expired"
	}
	unused := false
	if status == "active" {
		ref := t.CreatedAt
		if t.LastUsedAt != nil {
			ref = *t.LastUsedAt
		}
		if now.Sub(ref) >= time.Duration(unusedWarnDays())*24*time.Hour {
			unused = true
		}
	}
	return PATPublic{
		ID:         t.ID,
		Name:       t.Name,
		Prefix:     t.Prefix,
		Scopes:     append([]string(nil), t.Scopes...),
		CreatedAt:  t.CreatedAt,
		ExpiresAt:  t.ExpiresAt,
		RevokedAt:  t.RevokedAt,
		LastUsedAt: t.LastUsedAt,
		Status:     status,
		UnusedWarn: unused,
	}
}

func randomHex(nBytes int) string {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return randomString(nBytes * 2)
	}
	return hex.EncodeToString(b)
}

func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return hex.EncodeToString([]byte(fmt.Sprintf("%d", time.Now().UnixNano())))[:n]
	}
	out := make([]byte, n)
	for i := range out {
		out[i] = letters[int(b[i])%len(letters)]
	}
	return string(out)
}

func envInt(key string, fallback int) int {
	n, err := strconv.Atoi(strings.TrimSpace(os.Getenv(key)))
	if err != nil || n < 1 {
		return fallback
	}
	return n
}

// DefaultTTLDays is the UI/API default lifetime.
func DefaultTTLDays() int {
	n := envInt("API_PAT_DEFAULT_TTL_DAYS", defaultPATTTLDays)
	max := MaxTTLDays()
	if n > max {
		return max
	}
	return n
}

// MaxTTLDays is the cap on ttl_days.
func MaxTTLDays() int {
	return envInt("API_PAT_MAX_TTL_DAYS", defaultPATMaxTTLDays)
}

func unusedWarnDays() int {
	return envInt("API_PAT_UNUSED_WARN_DAYS", defaultUnusedWarnDays)
}

// UnusedWarnDays is how long a PAT may sit unused before the UI warns.
func UnusedWarnDays() int {
	return unusedWarnDays()
}

// LooksLikePAT reports whether s uses the PAT prefix.
func LooksLikePAT(s string) bool {
	return strings.HasPrefix(strings.TrimSpace(s), PATPrefix)
}

// ParseTTLDays converts request ttl_days into a duration.
func ParseTTLDays(days *int) (time.Duration, error) {
	d := DefaultTTLDays()
	if days != nil {
		d = *days
	}
	if d < 1 {
		return 0, fmt.Errorf("%w: ttl_days must be >= 1", ErrInvalidTTL)
	}
	if d > MaxTTLDays() {
		return 0, fmt.Errorf("%w: max %d days", ErrInvalidTTL, MaxTTLDays())
	}
	return time.Duration(d) * 24 * time.Hour, nil
}
