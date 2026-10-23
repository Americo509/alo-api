package mailer

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
)

// MemoryOutbox é uma Outbox em memória, para testes e desenvolvimento.
type MemoryOutbox struct {
	mu   sync.Mutex
	rows map[uuid.UUID]*row
}

type row struct {
	item        Item
	availableAt time.Time
	lockedUntil time.Time
	dead        bool
	deadAt      time.Time
	lastError   string
}

// NewMemoryOutbox cria a fila.
func NewMemoryOutbox() *MemoryOutbox { return &MemoryOutbox{rows: map[uuid.UUID]*row{}} }

// Pending devolve quantos itens vivos (não mortos) existem.
func (m *MemoryOutbox) Pending() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, r := range m.rows {
		if !r.dead {
			n++
		}
	}
	return n
}

// DeadCount devolve quantos itens mortos existem.
func (m *MemoryOutbox) DeadCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, r := range m.rows {
		if r.dead {
			n++
		}
	}
	return n
}

// Payloads devolve os conteúdos (cifrados) dos itens vivos, para os testes
// conferirem que não há texto em claro.
func (m *MemoryOutbox) Payloads() [][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out [][]byte
	for _, r := range m.rows {
		out = append(out, append([]byte(nil), r.item.Payload...))
	}
	return out
}

func (m *MemoryOutbox) Enqueue(_ context.Context, it Item, availableAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rows[it.ID] = &row{item: it, availableAt: availableAt}
	return nil
}

func (m *MemoryOutbox) Claim(_ context.Context, now time.Time, limit int, lease time.Duration) ([]Item, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var ready []*row
	for _, r := range m.rows {
		if !r.dead && !r.availableAt.After(now) && !r.lockedUntil.After(now) {
			ready = append(ready, r)
		}
	}
	sort.Slice(ready, func(i, j int) bool { return ready[i].availableAt.Before(ready[j].availableAt) })
	if len(ready) > limit {
		ready = ready[:limit]
	}
	out := make([]Item, 0, len(ready))
	for _, r := range ready {
		r.item.Attempts++
		r.lockedUntil = now.Add(lease)
		out = append(out, r.item)
	}
	return out, nil
}

func (m *MemoryOutbox) Done(_ context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.rows, id)
	return nil
}

func (m *MemoryOutbox) Retry(_ context.Context, id uuid.UUID, next time.Time, errClass string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok := m.rows[id]; ok {
		r.availableAt, r.lockedUntil, r.lastError = next, time.Time{}, errClass
	}
	return nil
}

func (m *MemoryOutbox) Dead(_ context.Context, id uuid.UUID, now time.Time, errClass string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok := m.rows[id]; ok {
		r.dead, r.deadAt, r.lastError = true, now, errClass
		r.item.Payload = nil // o conteúdo some
	}
	return nil
}

func (m *MemoryOutbox) PurgeDead(_ context.Context, olderThan time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var n int64
	for id, r := range m.rows {
		if r.dead && r.deadAt.Before(olderThan) {
			delete(m.rows, id)
			n++
		}
	}
	return n, nil
}
