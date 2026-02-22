package server

import "time"

type TIHit struct {
	Key       string
	Category  string
	Malicious bool
	ExpiresAt time.Time
}

type TICache struct{ entries map[string]TIHit }

func NewTICache() *TICache { return &TICache{entries: map[string]TIHit{}} }

func (c *TICache) Get(key string) (TIHit, bool) {
	h, ok := c.entries[key]
	if !ok || time.Now().After(h.ExpiresAt) {
		return TIHit{}, false
	}
	return h, true
}

func (c *TICache) Set(key, category string, malicious bool, ttl time.Duration) {
	c.entries[key] = TIHit{Key: key, Category: category, Malicious: malicious, ExpiresAt: time.Now().Add(ttl)}
}
