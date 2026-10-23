package lease

import (
	"context"
	"sync"
	"time"

	"github.com/Americo509/alo-api/internal/clock"
)

// MemoryBackend é um Backend em memória com expiração pelo relógio injetado.
// Para testes e para rodar um único worker localmente.
type MemoryBackend struct {
	mu     sync.Mutex
	clock  clock.Clock
	leases map[string]memLease
	fences map[string]int64
	// Fail, se definido, é devolvido por todas as operações (simula Redis fora).
	Fail error
}

type memLease struct {
	owner   string
	expires time.Time
}

// NewMemoryBackend cria o backend.
func NewMemoryBackend(c clock.Clock) *MemoryBackend {
	return &MemoryBackend{clock: c, leases: map[string]memLease{}, fences: map[string]int64{}}
}

// SetFail liga/desliga a falha simulada de forma segura para concorrência.
func (m *MemoryBackend) SetFail(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Fail = err
}

func (m *MemoryBackend) current(id string) (memLease, bool) {
	l, ok := m.leases[id]
	if !ok || !m.clock.Now().Before(l.expires) {
		return memLease{}, false
	}
	return l, true
}

func (m *MemoryBackend) TryAcquire(_ context.Context, id, owner string, ttl time.Duration) (int64, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return 0, false, m.Fail
	}
	if _, held := m.current(id); held {
		return 0, false, nil
	}
	m.leases[id] = memLease{owner: owner, expires: m.clock.Now().Add(ttl)}
	m.fences[id]++
	return m.fences[id], true, nil
}

func (m *MemoryBackend) Renew(_ context.Context, id, owner string, ttl time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return false, m.Fail
	}
	l, held := m.current(id)
	if !held || l.owner != owner {
		return false, nil
	}
	m.leases[id] = memLease{owner: owner, expires: m.clock.Now().Add(ttl)}
	return true, nil
}

func (m *MemoryBackend) Release(_ context.Context, id, owner string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Fail != nil {
		return m.Fail
	}
	if l, held := m.current(id); held && l.owner == owner {
		delete(m.leases, id)
	}
	return nil
}
