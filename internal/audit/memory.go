package audit

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/Americo509/alo-api/internal/clock"
)

// Memory é um Recorder/Reader em memória, para testes e desenvolvimento.
type Memory struct {
	mu     sync.Mutex
	clock  clock.Clock
	events []Event
}

// NewMemory cria o armazenamento.
func NewMemory(clk clock.Clock) *Memory { return &Memory{clock: clk} }

func (m *Memory) Record(_ context.Context, e Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	e = Sanitize(e)
	e.At = m.clock.Now()
	m.events = append(m.events, e)
	return nil
}

// All devolve todos os eventos na ordem de gravação (para os testes).
func (m *Memory) All() []Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Event(nil), m.events...)
}

// OfType devolve os eventos de um tipo.
func (m *Memory) OfType(t Type) []Event {
	var out []Event
	for _, e := range m.All() {
		if e.Type == t {
			out = append(out, e)
		}
	}
	return out
}

func (m *Memory) RecentByUser(_ context.Context, userID uuid.UUID, limit int) ([]Event, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Event
	for i := len(m.events) - 1; i >= 0 && len(out) < limit; i-- {
		if m.events[i].UserID == userID {
			out = append(out, m.events[i])
		}
	}
	return out, nil
}

func (m *Memory) DeleteOlderThan(_ context.Context, cutoff time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	kept := m.events[:0]
	var n int64
	for _, e := range m.events {
		if e.At.Before(cutoff) {
			n++
			continue
		}
		kept = append(kept, e)
	}
	m.events = kept
	return n, nil
}
