package resolver

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

type registryFile struct {
	Version int                                 `json:"version"`
	Anchors map[string]*TrustAnchorRegistration `json:"anchors"`
}

func (r *FederationResolver) loadRegistry() error {
	if r == nil || r.registryPath == "" {
		return nil
	}
	data, err := os.ReadFile(r.registryPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var file registryFile
	if err := json.Unmarshal(data, &file); err != nil {
		return fmt.Errorf("parse %s: %w", r.registryPath, err)
	}
	now := time.Now()
	loaded := 0
	skipped := 0
	r.registeredMu.Lock()
	defer r.registeredMu.Unlock()
	if r.registeredAnchors == nil {
		r.registeredAnchors = make(map[string]*TrustAnchorRegistration)
	}
	for id, reg := range file.Anchors {
		if reg == nil || id == "" {
			continue
		}
		if !reg.ExpiresAt.IsZero() && !now.Before(reg.ExpiresAt) {
			skipped++
			continue
		}
		if reg.EntityID == "" {
			reg.EntityID = id
		}
		r.registeredAnchors[reg.EntityID] = reg
		loaded++
	}
	log.Printf("[RESOLVER] Loaded %d trust-anchor registration(s) from %s (%d expired skipped)", loaded, r.registryPath, skipped)
	return nil
}

// saveRegistryLocked writes the map. Caller must hold registeredMu (read or write).
func (r *FederationResolver) saveRegistryLocked() error {
	if r == nil || r.registryPath == "" {
		return nil
	}
	file := registryFile{
		Version: 1,
		Anchors: make(map[string]*TrustAnchorRegistration, len(r.registeredAnchors)),
	}
	now := time.Now()
	for id, reg := range r.registeredAnchors {
		if reg == nil {
			continue
		}
		if !reg.ExpiresAt.IsZero() && !now.Before(reg.ExpiresAt) {
			continue
		}
		file.Anchors[id] = reg
	}
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(r.registryPath)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	tmp := r.registryPath + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, r.registryPath)
}

func (r *FederationResolver) persistAfterChange() {
	if r == nil || r.registryPath == "" {
		return
	}
	if err := r.saveRegistryLocked(); err != nil {
		log.Printf("[RESOLVER] Failed to persist trust-anchor registry: %v", err)
	}
}

// StartCacheJanitor removes expired cache slots until stop is closed.
func (r *FederationResolver) StartCacheJanitor(stop <-chan struct{}, interval time.Duration) {
	if r == nil || interval <= 0 {
		return
	}
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				r.SweepCaches()
			}
		}
	}()
}
