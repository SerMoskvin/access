package access

import (
	"sync"
	"time"
)

type cacheItem struct {
	value  interface{}
	expire time.Time
}

type memoryCache struct {
	mu    sync.RWMutex
	store map[string]cacheItem
	ttl   time.Duration
}

func NewCache(ttl time.Duration) *memoryCache {
	return &memoryCache{
		store: make(map[string]cacheItem),
		ttl:   ttl,
	}
}

func (c *memoryCache) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	item, exists := c.store[key]
	if !exists || time.Now().After(item.expire) {
		return nil, false
	}
	return item.value, true
}

func (c *memoryCache) Set(key string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.store[key] = cacheItem{
		value:  value,
		expire: time.Now().Add(c.ttl),
	}
}

func (c *memoryCache) Cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for k, v := range c.store {
			if now.After(v.expire) {
				delete(c.store, k)
			}
		}
		c.mu.Unlock()
	}
}

func (c *memoryCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.store = make(map[string]cacheItem)
}
