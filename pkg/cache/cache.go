package cache

import (
	"sync"
	"time"

	"resolver/pkg/metrics"
)

type Cache struct {
	data map[string]CacheEntry
	mu   sync.RWMutex
	name string
}

type CacheEntry struct {
	Value     interface{}
	ExpiresAt time.Time
}

func NewCache(name string) *Cache {
	c := &Cache{
		data: make(map[string]CacheEntry),
		name: name,
	}

	// Update cache size metric initially
	metrics.UpdateCacheSize(name, 0)

	return c
}

func (c *Cache) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.data[key]
	if !exists || time.Now().After(entry.ExpiresAt) {
		metrics.RecordCacheMiss(c.name, key)
		return nil, false
	}

	metrics.RecordCacheHit(c.name, key)
	return entry.Value, true
}

func (c *Cache) Set(key string, value interface{}, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.data[key] = CacheEntry{
		Value:     value,
		ExpiresAt: time.Now().Add(ttl),
	}

	// Update cache size metric
	metrics.UpdateCacheSize(c.name, len(c.data))
}

func (c *Cache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.data)
}

func (c *Cache) Remove(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, exists := c.data[key]; exists {
		delete(c.data, key)
		// Update cache size metric
		metrics.UpdateCacheSize(c.name, len(c.data))
		return true
	}
	return false
}
