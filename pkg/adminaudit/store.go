package adminaudit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	defaultAuditMaxEntries = 5000
	auditFileName          = "admin.jsonl"
)

// Entry is one mutating admin request recorded on the node.
type Entry struct {
	ID     string `json:"id"`
	TS     string `json:"ts"`
	Action string `json:"action"`
	Method string `json:"method"`
	Path   string `json:"path"`
	Status int    `json:"status"`
	Actor  string `json:"actor,omitempty"`
	Auth   string `json:"auth,omitempty"`
	Token  string `json:"token,omitempty"`
}

// Store is an append-only JSONL log under $DATA_PATH/audit/.
type Store struct {
	mu      sync.Mutex
	path    string
	max     int
	entries []Entry
}

var (
	globalMu    sync.RWMutex
	globalStore *Store
)

// Init opens (or creates) the node audit log and sets the process-global instance.
func Init(dataPath string) (*Store, error) {
	s := &Store{max: defaultAuditMaxEntries}
	if strings.TrimSpace(dataPath) != "" {
		dir := filepath.Join(dataPath, "audit")
		if err := os.MkdirAll(dir, 0750); err != nil {
			return nil, fmt.Errorf("admin audit store: mkdir: %w", err)
		}
		s.path = filepath.Join(dir, auditFileName)
		if err := s.load(); err != nil {
			return nil, err
		}
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

// SetForTest installs a store for tests. Pass nil to clear.
func SetForTest(s *Store) {
	globalMu.Lock()
	defer globalMu.Unlock()
	globalStore = s
}

func (s *Store) load() error {
	f, err := os.Open(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("admin audit store: read: %w", err)
	}
	defer func() { _ = f.Close() }()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var out []Entry
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			continue
		}
		out = append(out, e)
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("admin audit store: scan: %w", err)
	}
	if n := len(out) - s.max; n > 0 {
		out = out[n:]
	}
	s.entries = out
	return nil
}

// Append records one event (newest last on disk; List returns newest first).
func (s *Store) Append(e Entry) error {
	if s == nil {
		return nil
	}
	if e.TS == "" {
		e.TS = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if e.ID == "" {
		e.ID = fmt.Sprintf("a_%d", time.Now().UnixNano())
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = append(s.entries, e)
	if s.path == "" {
		if extra := len(s.entries) - s.max; extra > 0 {
			s.entries = s.entries[extra:]
		}
		return nil
	}
	if err := s.appendLineLocked(e); err != nil {
		return err
	}
	if len(s.entries) > s.max+s.max/10 {
		return s.compactLocked()
	}
	return nil
}

func (s *Store) appendLineLocked(e Entry) error {
	raw, err := json.Marshal(e)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(s.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return fmt.Errorf("admin audit store: open: %w", err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.Write(append(raw, '\n')); err != nil {
		return fmt.Errorf("admin audit store: write: %w", err)
	}
	return nil
}

func (s *Store) compactLocked() error {
	if len(s.entries) > s.max {
		s.entries = append([]Entry(nil), s.entries[len(s.entries)-s.max:]...)
	}
	if s.path == "" {
		return nil
	}
	tmp := s.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0640)
	if err != nil {
		return fmt.Errorf("admin audit store: compact open: %w", err)
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	for _, e := range s.entries {
		raw, err := json.Marshal(e)
		if err != nil {
			return err
		}
		if _, err := f.Write(append(raw, '\n')); err != nil {
			return fmt.Errorf("admin audit store: compact write: %w", err)
		}
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("admin audit store: compact rename: %w", err)
	}
	ok = true
	return nil
}

// List returns a copy of entries, newest first.
func (s *Store) List() []Entry {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Entry, len(s.entries))
	for i, e := range s.entries {
		out[len(s.entries)-1-i] = e
	}
	return out
}

// Record appends to the process store if it is initialized.
func Record(e Entry) {
	store := Get()
	if store == nil {
		return
	}
	if err := store.Append(e); err != nil {
		log.Printf("[WARN] admin audit store: %v", err)
	}
}

// Action is a catalog-style name for a mutating admin request.
func Action(method, path string) string {
	method = strings.ToUpper(strings.TrimSpace(method))
	p := strings.Trim(path, "/")
	if strings.HasPrefix(p, "admin/v1/") || p == "admin/v1" {
		rel := strings.TrimPrefix(p, "admin/v1")
		rel = strings.TrimPrefix(rel, "/")
		if op := adminV1Action(method, rel); op != "" {
			return op
		}
	}
	if method == "" {
		return p
	}
	return strings.ToLower(method) + " " + "/" + p
}

func adminV1Action(method, rel string) string {
	segs := strings.Split(strings.Trim(rel, "/"), "/")
	if len(segs) == 1 && segs[0] == "" {
		return ""
	}
	switch segs[0] {
	case "audit":
		return "audit.list"
	case "configuration":
		if len(segs) >= 2 && segs[1] == "statement" {
			return "configuration.statement"
		}
		switch method {
		case "PUT":
			return "configuration.replace"
		case "PATCH":
			return "configuration.patch"
		}
	case "keys":
		if len(segs) >= 3 && segs[2] == "rotate" {
			return "keys.rotate"
		}
		if len(segs) == 1 {
			if method == "POST" {
				return "keys.create"
			}
			return ""
		}
		if method == "DELETE" {
			return "keys.delete"
		}
	case "tokens":
		if len(segs) == 1 {
			if method == "POST" {
				return "tokens.create"
			}
			return ""
		}
		if method == "DELETE" {
			return "tokens.revoke"
		}
	case "cache":
		if len(segs) < 2 {
			return ""
		}
		switch segs[1] {
		case "clear-all":
			return "cache.clear_all"
		case "clear-entities":
			return "cache.clear_entities"
		case "clear-chains":
			return "cache.clear_chains"
		case "entity":
			if method == "DELETE" {
				return "cache.entity.delete"
			}
		case "chain":
			if method == "DELETE" {
				return "cache.chain.delete"
			}
		}
	}
	return ""
}
