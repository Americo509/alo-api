package tenant

import (
	"bytes"
	"context"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

type inviteRow struct {
	inv      Invitation
	hash     []byte
	accepted bool
	revoked  bool
}

// InviteMemory é um InviteStore em memória; compartilha o estado de membros
// com o Memory para que Accept crie o vínculo.
type InviteMemory struct {
	mu   sync.Mutex
	mem  *Memory
	rows []*inviteRow
}

// NewInviteMemory cria o store sobre o Memory de tenants.
func NewInviteMemory(m *Memory) *InviteMemory { return &InviteMemory{mem: m} }

func (r *inviteRow) pending(now time.Time) bool {
	return !r.accepted && !r.revoked && now.Before(r.inv.ExpiresAt)
}

// Create implementa InviteStore.
func (s *InviteMemory) Create(_ context.Context, inv Invitation, hash []byte, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	pending := 0
	for _, r := range s.rows {
		if r.inv.TenantID != inv.TenantID || r.accepted || r.revoked {
			continue
		}
		if strings.EqualFold(r.inv.Email, inv.Email) {
			r.revoked = true
			continue
		}
		if r.pending(now) {
			pending++
		}
	}
	if pending >= MaxPendingInvites {
		return ErrTooManyInvites
	}
	s.rows = append(s.rows, &inviteRow{inv: inv, hash: append([]byte(nil), hash...)})
	return nil
}

func (s *InviteMemory) find(hash []byte) *inviteRow {
	for _, r := range s.rows {
		if bytes.Equal(r.hash, hash) {
			return r
		}
	}
	return nil
}

// Find implementa InviteStore.
func (s *InviteMemory) Find(_ context.Context, hash []byte) (Invitation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r := s.find(hash); r != nil {
		return r.inv, nil
	}
	return Invitation{}, ErrInvalidInvite
}

// Accept implementa InviteStore.
func (s *InviteMemory) Accept(ctx context.Context, hash []byte, userID uuid.UUID, email string, now time.Time) (Invitation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := s.find(hash)
	if r == nil || !r.pending(now) || !strings.EqualFold(r.inv.Email, email) {
		return Invitation{}, ErrInvalidInvite
	}
	t, err := s.mem.Get(ctx, r.inv.TenantID)
	if err != nil || t.Status != StatusActive {
		return Invitation{}, ErrInvalidInvite
	}
	if err := s.mem.AddMember(ctx, r.inv.TenantID, userID, r.inv.Role); err != nil {
		return Invitation{}, err // ErrAlreadyMember não consome o convite
	}
	r.accepted = true
	return r.inv, nil
}

// Pending implementa InviteStore.
func (s *InviteMemory) Pending(_ context.Context, tenantID uuid.UUID, now time.Time) ([]Invitation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Invitation
	for _, r := range s.rows {
		if r.inv.TenantID == tenantID && r.pending(now) {
			out = append(out, r.inv)
		}
	}
	return out, nil
}

// Revoke implementa InviteStore.
func (s *InviteMemory) Revoke(_ context.Context, tenantID, id uuid.UUID, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, r := range s.rows {
		if r.inv.ID == id && r.inv.TenantID == tenantID && r.pending(now) {
			r.revoked = true
			return nil
		}
	}
	return ErrNotFound
}
