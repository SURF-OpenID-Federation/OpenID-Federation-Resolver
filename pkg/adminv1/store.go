package adminv1

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const stateFileName = "state.json"

// Store persists Administration API overlay state under $DATA_PATH/admin-v1.
type Store struct {
	path string
	mu   sync.Mutex
	data State
}

// State is the on-disk overlay.
type State struct {
	Configuration *ConfigurationOverlay `json:"configuration,omitempty"`
}

// ConfigurationOverlay is operator-written Entity Configuration claims.
type ConfigurationOverlay struct {
	Lifetime         int64                     `json:"lifetime,omitempty"`
	AuthorityHints   []string                  `json:"authority_hints,omitempty"`
	TrustAnchorHints []string                  `json:"trust_anchor_hints,omitempty"`
	Metadata         map[string]map[string]any `json:"metadata,omitempty"`
	TrustMarks       []map[string]any          `json:"trust_marks,omitempty"`
	Crit             []string                  `json:"crit,omitempty"`
	Extra            map[string]any            `json:"extra,omitempty"`
	UpdatedAt        int64                     `json:"updated_at,omitempty"`
}

// Open loads or creates the admin-v1 store.
func Open(dataDir string) (*Store, error) {
	if dataDir == "" {
		dataDir = "./data"
	}
	dir := filepath.Join(dataDir, "admin-v1")
	if err := os.MkdirAll(dir, 0750); err != nil {
		return nil, fmt.Errorf("admin-v1 store: mkdir: %w", err)
	}
	s := &Store{path: filepath.Join(dir, stateFileName)}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) load() error {
	raw, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("admin-v1 store: read: %w", err)
	}
	if err := json.Unmarshal(raw, &s.data); err != nil {
		return fmt.Errorf("admin-v1 store: parse: %w", err)
	}
	return nil
}

func (s *Store) saveLocked() error {
	raw, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0640); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// Configuration returns a copy of the overlay (may be nil).
func (s *Store) Configuration() *ConfigurationOverlay {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.data.Configuration == nil {
		return nil
	}
	cp := *s.data.Configuration
	return &cp
}

// SetConfiguration replaces the configuration overlay.
func (s *Store) SetConfiguration(cfg *ConfigurationOverlay) error {
	if s == nil {
		return fmt.Errorf("admin-v1 store is not open")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if cfg != nil {
		cfg.UpdatedAt = time.Now().Unix()
	}
	s.data.Configuration = cfg
	return s.saveLocked()
}

// LifetimeSeconds returns the configured Entity Configuration lifetime.
func (s *Store) LifetimeSeconds() int64 {
	if s == nil {
		return DefaultLifetime
	}
	cfg := s.Configuration()
	if cfg == nil || cfg.Lifetime < 1 {
		return DefaultLifetime
	}
	return cfg.Lifetime
}
