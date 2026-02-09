package revocation

import (
	"context"
	"sync"
	"time"
)

type DenyList struct {
	mu      sync.RWMutex
	entries map[string]time.Time // JWE SHA-256 hash -> expiry
}

func NewDenyList() *DenyList {
	return &DenyList{
		entries: make(map[string]time.Time),
	}
}

func (d *DenyList) Add(hash string, expiresAt time.Time) {
	d.mu.Lock()
	d.entries[hash] = expiresAt
	d.mu.Unlock()
}

func (d *DenyList) IsRevoked(hash string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	exp, ok := d.entries[hash]
	if !ok {
		return false
	}
	return time.Now().Before(exp)
}

func (d *DenyList) Cleanup() {
	now := time.Now()
	d.mu.Lock()
	for hash, exp := range d.entries {
		if now.After(exp) {
			delete(d.entries, hash)
		}
	}
	d.mu.Unlock()
}

func (d *DenyList) StartCleanup(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				d.Cleanup()
			}
		}
	}()
}
