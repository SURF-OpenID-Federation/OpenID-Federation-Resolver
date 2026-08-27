package cache

import (
	"strings"
	"sync"
	"time"

	"resolver/pkg/metrics"
)

type Cache struct {
	data       map[string]CacheEntry
	mu         sync.RWMutex
	name       string
	maxEntries int
}

type CacheEntry struct {
	Value     interface{}
	ExpiresAt time.Time
}

func NewCache(name string) *Cache {
	return NewLimitedCache(name, 0)
}

func NewLimitedCache(name string, maxEntries int) *Cache {
	c := &Cache{
		data:       make(map[string]CacheEntry),
		name:       name,
		maxEntries: maxEntries,
	}
	metrics.UpdateCacheSize(name, 0)
	return c
}

func (c *Cache) SetMaxEntries(n int) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.maxEntries = n
	c.evictLocked(time.Now())
	metrics.UpdateCacheSize(c.name, len(c.data))
}

func (c *Cache) MaxEntries() int {
	if c == nil {
		return 0
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.maxEntries
}

func (c *Cache) Get(key string) (interface{}, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, exists := c.data[key]
	if !exists {
		metrics.RecordCacheMiss(c.name, key)
		return nil, false
	}
	if time.Now().After(entry.ExpiresAt) {
		delete(c.data, key)
		metrics.UpdateCacheSize(c.name, len(c.data))
		metrics.RecordCacheMiss(c.name, key)
		return nil, false
	}

	metrics.RecordCacheHit(c.name, key)
	return entry.Value, true
}

func (c *Cache) Set(key string, value interface{}, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if ttl <= 0 {
		delete(c.data, key)
		metrics.UpdateCacheSize(c.name, len(c.data))
		return
	}

	now := time.Now()
	c.data[key] = CacheEntry{
		Value:     value,
		ExpiresAt: now.Add(ttl),
	}
	c.evictLocked(now)
	metrics.UpdateCacheSize(c.name, len(c.data))
}

func (c *Cache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	now := time.Now()
	n := 0
	for _, entry := range c.data {
		if !now.After(entry.ExpiresAt) {
			n++
		}
	}
	return n
}

// Items returns a snapshot of non-expired entries without recording hit/miss metrics.
func (c *Cache) Items() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()
	now := time.Now()
	out := make(map[string]interface{}, len(c.data))
	for k, entry := range c.data {
		if now.After(entry.ExpiresAt) {
			continue
		}
		out[k] = entry.Value
	}
	return out
}

func (c *Cache) Remove(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.data[key]; exists {
		delete(c.data, key)
		metrics.UpdateCacheSize(c.name, len(c.data))
		return true
	}
	return false
}

// RemoveExactOrPrefixed deletes key and every "key:…" slot (chain aliases).
func (c *Cache) RemoveExactOrPrefixed(key string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	prefix := key + ":"
	for k := range c.data {
		if k == key || strings.HasPrefix(k, prefix) {
			delete(c.data, k)
			n++
		}
	}
	if n > 0 {
		metrics.UpdateCacheSize(c.name, len(c.data))
	}
	return n
}

// Sweep deletes expired entries. Returns how many were removed.
func (c *Cache) Sweep() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := c.sweepLocked(time.Now())
	if n > 0 {
		metrics.UpdateCacheSize(c.name, len(c.data))
	}
	return n
}

func (c *Cache) sweepLocked(now time.Time) int {
	n := 0
	for k, entry := range c.data {
		if now.After(entry.ExpiresAt) {
			delete(c.data, k)
			n++
		}
	}
	return n
}

func (c *Cache) evictLocked(now time.Time) {
	c.sweepLocked(now)
	if c.maxEntries <= 0 || len(c.data) <= c.maxEntries {
		return
	}
	for len(c.data) > c.maxEntries {
		var victim string
		var soonest time.Time
		first := true
		for k, entry := range c.data {
			if first || entry.ExpiresAt.Before(soonest) {
				victim = k
				soonest = entry.ExpiresAt
				first = false
			}
		}
		if victim == "" {
			return
		}
		delete(c.data, victim)
	}
}
