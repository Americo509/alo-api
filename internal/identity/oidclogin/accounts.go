package oidclogin

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Americo509/alo-api/internal/identity"
	"github.com/Americo509/alo-api/internal/storage/postgres"
)

// Accounts é o acesso às contas que o login federado precisa. As duas
// operações de escrita são ATÔMICAS: criar usuário + vínculo, ou nada.
type Accounts interface {
	FindByIdentity(ctx context.Context, issuer, subject string) (identity.User, error) // identity.ErrNotFound
	GetUserByEmail(ctx context.Context, email string) (identity.User, error)           // identity.ErrNotFound
	GetUser(ctx context.Context, id uuid.UUID) (identity.User, error)                  // identity.ErrNotFound
	// CreateWithIdentity cria o usuário já com o vínculo. identity.ErrEmailTaken
	// se o e-mail existe; identity.ErrIdentityDup se (issuer, subject) existe.
	CreateWithIdentity(ctx context.Context, email, displayName string, emailVerified bool, issuer, subject string) (identity.User, error)
	// LinkIdentity vincula a um usuário existente. identity.ErrIdentityDup se
	// (issuer, subject) já pertence a alguém.
	LinkIdentity(ctx context.Context, userID uuid.UUID, issuer, subject, email string) error
}

// --- Postgres ---------------------------------------------------------------

// PGAccounts implementa Accounts sobre o schema ident.
type PGAccounts struct {
	pool postgres.Beginner
	repo *identity.Repo
}

// NewPGAccounts cria o armazenamento. repo deve usar o mesmo pool.
func NewPGAccounts(pool postgres.Beginner, repo *identity.Repo) *PGAccounts {
	return &PGAccounts{pool: pool, repo: repo}
}

func (a *PGAccounts) FindByIdentity(ctx context.Context, issuer, subject string) (identity.User, error) {
	return a.repo.FindByIdentity(ctx, issuer, subject)
}

func (a *PGAccounts) GetUserByEmail(ctx context.Context, email string) (identity.User, error) {
	return a.repo.GetUserByEmail(ctx, email)
}

func (a *PGAccounts) GetUser(ctx context.Context, id uuid.UUID) (identity.User, error) {
	return a.repo.GetUser(ctx, id)
}

func (a *PGAccounts) CreateWithIdentity(ctx context.Context, email, name string, verified bool, issuer, subject string) (identity.User, error) {
	var u identity.User
	err := pgx.BeginTxFunc(ctx, a.pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		r := identity.NewRepo(tx)
		var err error
		if u, err = r.CreateUser(ctx, email, name, verified); err != nil {
			return err
		}
		_, err = r.LinkIdentity(ctx, u.ID, issuer, subject, email)
		return err
	})
	if err != nil {
		return identity.User{}, err
	}
	return u, nil
}

func (a *PGAccounts) LinkIdentity(ctx context.Context, userID uuid.UUID, issuer, subject, email string) error {
	_, err := a.repo.LinkIdentity(ctx, userID, issuer, subject, email)
	return err
}

// --- memória ------------------------------------------------------------------

// MemoryAccounts é um Accounts em memória, para testes e desenvolvimento.
type MemoryAccounts struct {
	mu     sync.Mutex
	users  map[uuid.UUID]identity.User
	idents map[string]uuid.UUID // issuer|subject -> usuário
}

// NewMemoryAccounts cria o armazenamento.
func NewMemoryAccounts() *MemoryAccounts {
	return &MemoryAccounts{users: map[uuid.UUID]identity.User{}, idents: map[string]uuid.UUID{}}
}

// AddUser insere um usuário já existente (por exemplo, uma conta com senha).
func (m *MemoryAccounts) AddUser(u identity.User) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users[u.ID] = u
}

// SetStatus altera a situação de um usuário (testes de conta suspensa).
func (m *MemoryAccounts) SetStatus(id uuid.UUID, s identity.Status) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u := m.users[id]
	u.Status = s
	m.users[id] = u
}

// Identities devolve quantos vínculos existem (para os testes).
func (m *MemoryAccounts) Identities() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.idents)
}

func key(issuer, subject string) string { return issuer + "|" + subject }

func (m *MemoryAccounts) byEmailLocked(email string) (identity.User, bool) {
	for _, u := range m.users {
		if strings.EqualFold(u.Email, email) {
			return u, true
		}
	}
	return identity.User{}, false
}

func (m *MemoryAccounts) FindByIdentity(_ context.Context, issuer, subject string) (identity.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.idents[key(issuer, subject)]
	if !ok {
		return identity.User{}, identity.ErrNotFound
	}
	return m.users[id], nil
}

func (m *MemoryAccounts) GetUserByEmail(_ context.Context, email string) (identity.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if u, ok := m.byEmailLocked(email); ok {
		return u, nil
	}
	return identity.User{}, identity.ErrNotFound
}

func (m *MemoryAccounts) GetUser(_ context.Context, id uuid.UUID) (identity.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[id]
	if !ok {
		return identity.User{}, identity.ErrNotFound
	}
	return u, nil
}

func (m *MemoryAccounts) CreateWithIdentity(_ context.Context, email, name string, verified bool, issuer, subject string) (identity.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, taken := m.byEmailLocked(email); taken {
		return identity.User{}, identity.ErrEmailTaken
	}
	if _, dup := m.idents[key(issuer, subject)]; dup {
		return identity.User{}, identity.ErrIdentityDup
	}
	u := identity.User{
		ID: uuid.New(), Email: email, EmailVerified: verified, DisplayName: name,
		Status: identity.StatusActive, CreatedAt: time.Time{},
	}
	m.users[u.ID] = u
	m.idents[key(issuer, subject)] = u.ID
	return u, nil
}

func (m *MemoryAccounts) LinkIdentity(_ context.Context, userID uuid.UUID, issuer, subject, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, dup := m.idents[key(issuer, subject)]; dup {
		return identity.ErrIdentityDup
	}
	if _, ok := m.users[userID]; !ok {
		return errors.New("oidclogin: usuário inexistente")
	}
	m.idents[key(issuer, subject)] = userID
	return nil
}
