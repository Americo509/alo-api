package tenant

import (
	"context"
	"sync"

	"github.com/google/uuid"

	"github.com/Americo509/alo-api/internal/identity"
)

// Memory é um Store em memória para testes dos consumidores.
type Memory struct {
	mu      sync.Mutex
	tenants map[uuid.UUID]Tenant
	members map[uuid.UUID]map[uuid.UUID]Member
	// Profiles dá e-mail e nome aos membros (o PG faz join com ident.users).
	Profiles map[uuid.UUID]identity.User
}

// NewMemory cria o Store.
func NewMemory() *Memory {
	return &Memory{
		tenants:  map[uuid.UUID]Tenant{},
		members:  map[uuid.UUID]map[uuid.UUID]Member{},
		Profiles: map[uuid.UUID]identity.User{},
	}
}

// Create implementa Store.
func (m *Memory) Create(_ context.Context, t Tenant) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tenants[t.ID] = t
	m.members[t.ID] = map[uuid.UUID]Member{t.CreatedBy: m.member(t.ID, t.CreatedBy, identity.RoleOwner)}
	return nil
}

func (m *Memory) member(tid, uid uuid.UUID, r identity.Role) Member {
	p := m.Profiles[uid]
	return Member{UserID: uid, TenantID: tid, Role: r, Email: p.Email, DisplayName: p.DisplayName}
}

// Get implementa Store.
func (m *Memory) Get(_ context.Context, id uuid.UUID) (Tenant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tenants[id]
	if !ok {
		return Tenant{}, ErrNotFound
	}
	return t, nil
}

// SetStatus implementa Store.
func (m *Memory) SetStatus(_ context.Context, id uuid.UUID, s Status) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tenants[id]
	if !ok {
		return ErrNotFound
	}
	t.Status = s
	m.tenants[id] = t
	return nil
}

// Rename implementa Store.
func (m *Memory) Rename(_ context.Context, id uuid.UUID, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tenants[id]
	if !ok {
		return ErrNotFound
	}
	t.Name = name
	m.tenants[id] = t
	return nil
}

// OwnedCount implementa Store.
func (m *Memory) OwnedCount(_ context.Context, userID uuid.UUID) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, mem := range m.members {
		if x, ok := mem[userID]; ok && x.Role == identity.RoleOwner {
			n++
		}
	}
	return n, nil
}

// Member implementa Store.
func (m *Memory) Member(_ context.Context, tid, uid uuid.UUID) (Member, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	x, ok := m.members[tid][uid]
	if !ok {
		return Member{}, ErrNotFound
	}
	return x, nil
}

// Members implementa Store.
func (m *Memory) Members(_ context.Context, tid uuid.UUID) ([]Member, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Member, 0, len(m.members[tid]))
	for _, x := range m.members[tid] {
		out = append(out, x)
	}
	return out, nil
}

// MembershipsOf implementa Store.
func (m *Memory) MembershipsOf(_ context.Context, uid uuid.UUID) ([]Membership, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Membership
	for tid, mem := range m.members {
		if x, ok := mem[uid]; ok {
			out = append(out, Membership{Tenant: m.tenants[tid], Role: x.Role})
		}
	}
	return out, nil
}

// AddMember implementa Store.
func (m *Memory) AddMember(_ context.Context, tid, uid uuid.UUID, role identity.Role) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.tenants[tid]; !ok {
		return ErrNotFound
	}
	if _, ok := m.members[tid][uid]; ok {
		return ErrAlreadyMember
	}
	m.members[tid][uid] = m.member(tid, uid, role)
	return nil
}

func (m *Memory) owners(tid uuid.UUID) int {
	n := 0
	for _, x := range m.members[tid] {
		if x.Role == identity.RoleOwner {
			n++
		}
	}
	return n
}

// SetRole implementa Store.
func (m *Memory) SetRole(_ context.Context, tid, uid uuid.UUID, expect, role identity.Role) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	x, ok := m.members[tid][uid]
	if !ok {
		return ErrNotFound
	}
	if x.Role != expect {
		return ErrStale
	}
	if x.Role == identity.RoleOwner && role != identity.RoleOwner && m.owners(tid) <= 1 {
		return ErrLastOwner
	}
	x.Role = role
	m.members[tid][uid] = x
	return nil
}

// RemoveMember implementa Store.
func (m *Memory) RemoveMember(_ context.Context, tid, uid uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	x, ok := m.members[tid][uid]
	if !ok {
		return ErrNotFound
	}
	if x.Role == identity.RoleOwner && m.owners(tid) <= 1 {
		return ErrLastOwner
	}
	delete(m.members[tid], uid)
	return nil
}
