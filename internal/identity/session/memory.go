package session

import (
	"context"
	"sync"
	"time"

	"github.com/Americo509/alo-api/internal/clock"
)

// MemoryBackend é um Backend em memória com expiração pelo relógio injetado.
// Para testes e para rodar um único nó em desenvolvimento.
type MemoryBackend struct {
	mu    sync.Mutex
	clock clock.Clock
	kv    map[string]entry
	sets  map[string]map[string]time.Time
}

type entry struct {
	val     []byte
	expires time.Time
}

// NewMemoryBackend cria o backend.
func NewMemoryBackend(clk clock.Clock) *MemoryBackend {
	return &MemoryBackend{clock: clk, kv: map[string]entry{}, sets: map[string]map[string]time.Time{}}
}

func (b *MemoryBackend) live(e entry) bool { return b.clock.Now().Before(e.expires) }

func (b *MemoryBackend) Set(_ context.Context, key string, value []byte, ttl time.Duration) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	cp := make([]byte, len(value))
	copy(cp, value)
	b.kv[key] = entry{val: cp, expires: b.clock.Now().Add(ttl)}
	return nil
}

func (b *MemoryBackend) Get(_ context.Context, key string) ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	e, ok := b.kv[key]
	if !ok || !b.live(e) {
		if ok {
			delete(b.kv, key)
		}
		return nil, ErrNotFound
	}
	cp := make([]byte, len(e.val))
	copy(cp, e.val)
	return cp, nil
}

func (b *MemoryBackend) Del(_ context.Context, keys ...string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, k := range keys {
		delete(b.kv, k)
		delete(b.sets, k)
	}
	return nil
}

func (b *MemoryBackend) Expire(_ context.Context, key string, ttl time.Duration) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if e, ok := b.kv[key]; ok && b.live(e) {
		e.expires = b.clock.Now().Add(ttl)
		b.kv[key] = e
	}
	if s, ok := b.sets[key]; ok {
		exp := b.clock.Now().Add(ttl)
		for m := range s {
			s[m] = exp
		}
	}
	return nil
}

func (b *MemoryBackend) SetAdd(_ context.Context, set, member string, ttl time.Duration) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.sets[set] == nil {
		b.sets[set] = map[string]time.Time{}
	}
	b.sets[set][member] = b.clock.Now().Add(ttl)
	return nil
}

func (b *MemoryBackend) SetMembers(_ context.Context, set string) ([]string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var out []string
	for m, exp := range b.sets[set] {
		if b.clock.Now().Before(exp) {
			out = append(out, m)
		} else {
			delete(b.sets[set], m)
		}
	}
	return out, nil
}

func (b *MemoryBackend) SetRem(_ context.Context, set, member string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if s, ok := b.sets[set]; ok {
		delete(s, member)
	}
	return nil
}
