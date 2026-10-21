// Package identity modela os usuários humanos do painel e seus vínculos com
// tenants (ADR-0007). Identidade é global à plataforma; a autorização por
// tenant vem dos papéis em memberships.
package identity

import (
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Role é o papel de um usuário dentro de um tenant (ADR-0007, Q16).
type Role string

const (
	RoleOwner    Role = "dono"     // controle total do tenant, incluindo cobrança
	RoleAdmin    Role = "admin"    // configura instâncias, API keys, webhooks
	RoleOperator Role = "operador" // atende conversas
	RoleReader   Role = "leitura"  // só leitura
)

var roleRank = map[Role]int{RoleReader: 1, RoleOperator: 2, RoleAdmin: 3, RoleOwner: 4}

// Valid informa se o papel é conhecido.
func (r Role) Valid() bool { _, ok := roleRank[r]; return ok }

// AtLeast informa se r tem no mínimo o nível de min (dono > admin > operador > leitura).
func (r Role) AtLeast(min Role) bool { return roleRank[r] >= roleRank[min] }

// Status é a situação da conta do usuário.
type Status string

const (
	StatusActive    Status = "ativo"
	StatusSuspended Status = "suspenso"
	StatusDisabled  Status = "desativado"
)

// User é um usuário humano.
type User struct {
	ID            uuid.UUID
	Email         string
	EmailVerified bool
	DisplayName   string
	Status        Status
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// CanLogIn informa se o usuário pode iniciar sessão.
func (u User) CanLogIn() bool { return u.Status == StatusActive }

// Identity é uma identidade federada vinculada (issuer+subject).
type Identity struct {
	ID      uuid.UUID
	UserID  uuid.UUID
	Issuer  string
	Subject string
	Email   string
}

// Membership é o vínculo de um usuário com um tenant.
type Membership struct {
	UserID   uuid.UUID
	TenantID uuid.UUID
	Role     Role
}

// NormalizeEmail normaliza um e-mail para armazenamento e comparação: apara
// espaços e passa para minúsculo. Valida o formato. NFKC não é aplicado aqui
// porque e-mails são ASCII na prática; a parte local preserva maiúsculas só
// se o provedor exigir — por simplicidade e segurança, tratamos como
// case-insensitive inteiro, o padrão da esmagadora maioria dos provedores.
func NormalizeEmail(raw string) (string, error) {
	e := strings.ToLower(strings.TrimSpace(raw))
	if len(e) == 0 || len(e) > 254 {
		return "", fmt.Errorf("identity: e-mail com tamanho inválido")
	}
	addr, err := mail.ParseAddress(e)
	if err != nil {
		return "", fmt.Errorf("identity: e-mail inválido: %w", err)
	}
	// ParseAddress aceita "Nome <e@x>"; exigimos o endereço puro.
	if addr.Address != e {
		return "", fmt.Errorf("identity: e-mail deve ser apenas o endereço")
	}
	return e, nil
}
