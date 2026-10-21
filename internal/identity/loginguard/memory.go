package loginguard

import (
	"context"
	"sync"
	"time"

	"github.com/zapgateway/zap-gateway/internal/clock"
)

// MemoryCounter é um Counter em memória com expiração pelo relógio injetado.
type MemoryCounter struct {
	mu    sync.Mutex
	clock clock.Clock
	m     map[string]counter
}

type counter struct {
	n       int64
	expires time.Time
}

// NewMemoryCounter cria o contador.
func NewMemoryCounter(clk clock.Clock) *MemoryCounter {
	return &MemoryCounter{clock: clk, m: map[string]counter{}}
}

func (c *MemoryCounter) Incr(_ context.Context, key string, window time.Duration) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.clock.Now()
	cur := c.m[key]
	if now.After(cur.expires) {
		cur = counter{}
	}
	cur.n++
	cur.expires = now.Add(window)
	c.m[key] = cur
	return cur.n, nil
}

func (c *MemoryCounter) Get(_ context.Context, key string) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cur, ok := c.m[key]
	if !ok || c.clock.Now().After(cur.expires) {
		return 0, nil
	}
	return cur.n, nil
}

func (c *MemoryCounter) Reset(_ context.Context, keys ...string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, k := range keys {
		delete(c.m, k)
	}
	return nil
}
