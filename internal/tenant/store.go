package tenant

import (
	"context"

	"github.com/google/uuid"

	"github.com/Americo509/alo-api/internal/identity"
)

// Store é a persistência. As operações que mexem em donos são atômicas: a
// invariante "ao menos um dono" não pode depender de ler-e-depois-gravar.
type Store interface {
	// Create grava o tenant e o vínculo de dono na mesma transação.
	Create(ctx context.Context, t Tenant) error
	Get(ctx context.Context, id uuid.UUID) (Tenant, error)
	SetStatus(ctx context.Context, id uuid.UUID, s Status) error
	Rename(ctx context.Context, id uuid.UUID, name string) error
	// OwnedCount: quantos tenants o usuário criou e ainda é dono (anti-abuso).
	OwnedCount(ctx context.Context, userID uuid.UUID) (int, error)

	Member(ctx context.Context, tenantID, userID uuid.UUID) (Member, error)
	Members(ctx context.Context, tenantID uuid.UUID) ([]Member, error)
	MembershipsOf(ctx context.Context, userID uuid.UUID) ([]Membership, error)
	// AddMember falha com ErrAlreadyMember se já existir.
	AddMember(ctx context.Context, tenantID, userID uuid.UUID, role identity.Role) error
	// SetRole e RemoveMember devolvem ErrLastOwner se deixariam o tenant sem dono.
	// SetRole exige que o papel atual seja expect (evita corrida: a decisão de
	// permissão foi tomada sobre o papel que o ator viu).
	SetRole(ctx context.Context, tenantID, userID uuid.UUID, expect, role identity.Role) error
	RemoveMember(ctx context.Context, tenantID, userID uuid.UUID) error
}

// ErrStale: o papel mudou entre a leitura e a gravação; o ator deve tentar de novo.
var ErrStale = errStale{}

type errStale struct{}

func (errStale) Error() string {
	return "tenant: o membro foi alterado por outra pessoa; tente novamente"
}
