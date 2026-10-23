package passkey

import (
	"bytes"
	"context"
	"slices"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

// MemoryCredentials é um Credentials em memória, para testes e desenvolvimento.
type MemoryCredentials struct {
	mu sync.Mutex
	m  map[string]Stored // chave: string(credentialID)
}

// NewMemoryCredentials cria o armazenamento.
func NewMemoryCredentials() *MemoryCredentials { return &MemoryCredentials{m: map[string]Stored{}} }

func (s *MemoryCredentials) ListByUser(_ context.Context, userID uuid.UUID) ([]Stored, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Stored
	for _, st := range s.m {
		if st.UserID == userID {
			out = append(out, st)
		}
	}
	slices.SortFunc(out, func(a, b Stored) int { return a.CreatedAt.Compare(b.CreatedAt) })
	return out, nil
}

func (s *MemoryCredentials) Add(_ context.Context, userID uuid.UUID, c webauthn.Credential, label string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, dup := s.m[string(c.ID)]; dup {
		return ErrDuplicate
	}
	s.m[string(c.ID)] = Stored{UserID: userID, Credential: c, Label: label, CreatedAt: now}
	return nil
}

func (s *MemoryCredentials) Find(_ context.Context, id []byte) (Stored, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.m[string(id)]
	if !ok {
		return Stored{}, ErrNotFound
	}
	return st, nil
}

func (s *MemoryCredentials) Update(_ context.Context, id []byte, c webauthn.Credential, usedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.m[string(id)]
	if !ok {
		return ErrNotFound
	}
	st.Credential, st.LastUsedAt = c, usedAt
	s.m[string(id)] = st
	return nil
}

func (s *MemoryCredentials) Delete(_ context.Context, userID uuid.UUID, id []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.m[string(id)]
	if !ok || !bytes.Equal(st.UserID[:], userID[:]) {
		return ErrNotFound
	}
	delete(s.m, string(id))
	return nil
}
