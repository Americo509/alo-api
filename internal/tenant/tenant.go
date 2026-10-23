// Package tenant gerencia organizações (tenants), seus membros e papéis. É o
// único lugar que decide "este usuário pode fazer X neste tenant" (via
// Authorize), usando a matriz de internal/authz.
package tenant

import (
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/Americo509/alo-api/internal/identity"
)

// Status do tenant. Suspenso (por abuso ou pela plataforma) bloqueia tudo.
type Status string

const (
	StatusActive    Status = "ativo"
	StatusSuspended Status = "suspenso"
)

// Tenant é uma organização cliente.
type Tenant struct {
	ID        uuid.UUID
	Name      string
	Status    Status
	CreatedBy uuid.UUID
	CreatedAt time.Time
}

// Member é um usuário dentro de um tenant.
type Member struct {
	UserID      uuid.UUID
	TenantID    uuid.UUID
	Role        identity.Role
	Email       string
	DisplayName string
	CreatedAt   time.Time
}

// Membership é um tenant visto pelo usuário (para o seletor do painel).
type Membership struct {
	Tenant Tenant
	Role   identity.Role
}

var (
	ErrNotFound        = errors.New("tenant: não encontrado")
	ErrForbidden       = errors.New("tenant: sem permissão")
	ErrSuspended       = errors.New("tenant: suspenso")
	ErrLastOwner       = errors.New("tenant: o tenant precisa de ao menos um dono")
	ErrLimitReached    = errors.New("tenant: limite de tenants por usuário atingido")
	ErrInvalidName     = errors.New("tenant: nome inválido")
	ErrEmailUnverified = errors.New("tenant: verifique o e-mail antes de criar um tenant")
	ErrInvalidRole     = errors.New("tenant: papel inválido")
	ErrSelfChange      = errors.New("tenant: não é possível alterar o próprio papel")
	ErrAlreadyMember   = errors.New("tenant: já é membro")
	ErrUserNotActive   = errors.New("tenant: usuário inativo")
)
