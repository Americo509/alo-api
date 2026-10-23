package tenant

import (
	"context"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/Americo509/alo-api/internal/authz"
	"github.com/Americo509/alo-api/internal/clock"
	"github.com/Americo509/alo-api/internal/identity"
)

// Users resolve usuários (identity.Repo satisfaz).
type Users interface {
	GetUser(ctx context.Context, id uuid.UUID) (identity.User, error)
}

// Service é a regra de negócio de tenants e membros.
type Service struct {
	store    Store
	users    Users
	clock    clock.Clock
	maxOwned int
	newID    func() uuid.UUID
}

// Options configura o serviço.
type Options struct {
	// MaxOwnedPerUser limita quantos tenants um usuário pode possuir (anti-abuso).
	MaxOwnedPerUser int
}

// NewService cria o serviço.
func NewService(store Store, users Users, clk clock.Clock, opt Options) *Service {
	if opt.MaxOwnedPerUser <= 0 {
		opt.MaxOwnedPerUser = 5
	}
	return &Service{store: store, users: users, clock: clk, maxOwned: opt.MaxOwnedPerUser, newID: uuid.New}
}

// CleanName valida e normaliza o nome: sem controle, 1 a 100 caracteres.
func CleanName(raw string) (string, error) {
	n := strings.Join(strings.Fields(raw), " ")
	if n == "" || utf8.RuneCountInString(n) > 100 {
		return "", ErrInvalidName
	}
	for _, r := range n {
		if unicode.IsControl(r) || !unicode.IsPrint(r) {
			return "", ErrInvalidName
		}
	}
	return n, nil
}

// Create cria um tenant tendo userID como dono. Exige e-mail verificado e
// conta ativa.
func (s *Service) Create(ctx context.Context, userID uuid.UUID, name string) (Tenant, error) {
	clean, err := CleanName(name)
	if err != nil {
		return Tenant{}, err
	}
	u, err := s.users.GetUser(ctx, userID)
	if err != nil {
		return Tenant{}, err
	}
	if !u.CanLogIn() {
		return Tenant{}, ErrUserNotActive
	}
	if !u.EmailVerified {
		return Tenant{}, ErrEmailUnverified
	}
	n, err := s.store.OwnedCount(ctx, userID)
	if err != nil {
		return Tenant{}, err
	}
	if n >= s.maxOwned {
		return Tenant{}, ErrLimitReached
	}
	t := Tenant{ID: s.newID(), Name: clean, Status: StatusActive, CreatedBy: userID, CreatedAt: s.clock.Now()}
	if err := s.store.Create(ctx, t); err != nil {
		return Tenant{}, err
	}
	return t, nil
}

// List devolve os tenants do usuário com o papel dele em cada um.
func (s *Service) List(ctx context.Context, userID uuid.UUID) ([]Membership, error) {
	return s.store.MembershipsOf(ctx, userID)
}

// Authorize é o ponto único de decisão: o usuário está ativo, é membro do
// tenant, o tenant não está suspenso e o papel tem a permissão. Quem não é
// membro recebe ErrNotFound (não revela a existência do tenant).
func (s *Service) Authorize(ctx context.Context, userID, tenantID uuid.UUID, perm authz.Permission) (Member, error) {
	u, err := s.users.GetUser(ctx, userID)
	if err != nil || !u.CanLogIn() {
		return Member{}, ErrForbidden
	}
	m, err := s.store.Member(ctx, tenantID, userID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return Member{}, ErrNotFound
		}
		return Member{}, err
	}
	t, err := s.store.Get(ctx, tenantID)
	if err != nil {
		return Member{}, err
	}
	if t.Status == StatusSuspended {
		return Member{}, ErrSuspended
	}
	if !authz.Can(m.Role, perm) {
		return Member{}, ErrForbidden
	}
	return m, nil
}

// Get devolve o tenant para quem pode lê-lo.
func (s *Service) Get(ctx context.Context, userID, tenantID uuid.UUID) (Tenant, error) {
	if _, err := s.Authorize(ctx, userID, tenantID, authz.TenantRead); err != nil {
		return Tenant{}, err
	}
	return s.store.Get(ctx, tenantID)
}

// Rename altera o nome.
func (s *Service) Rename(ctx context.Context, actor, tenantID uuid.UUID, name string) error {
	if _, err := s.Authorize(ctx, actor, tenantID, authz.TenantUpdate); err != nil {
		return err
	}
	clean, err := CleanName(name)
	if err != nil {
		return err
	}
	return s.store.Rename(ctx, tenantID, clean)
}

// Members lista os membros.
func (s *Service) Members(ctx context.Context, actor, tenantID uuid.UUID) ([]Member, error) {
	if _, err := s.Authorize(ctx, actor, tenantID, authz.MembersRead); err != nil {
		return nil, err
	}
	return s.store.Members(ctx, tenantID)
}

// AddMember adiciona um usuário existente e ativo (o convite por e-mail, passo
// 2b.2, chama isto ao ser aceito).
func (s *Service) AddMember(ctx context.Context, actor, tenantID, userID uuid.UUID, role identity.Role) error {
	am, err := s.Authorize(ctx, actor, tenantID, authz.MembersManage)
	if err != nil {
		return err
	}
	if !role.Valid() {
		return ErrInvalidRole
	}
	if !authz.CanAssign(am.Role, "", role) {
		return ErrForbidden
	}
	u, err := s.users.GetUser(ctx, userID)
	if err != nil || !u.CanLogIn() {
		return ErrUserNotActive
	}
	return s.store.AddMember(ctx, tenantID, userID, role)
}

// ChangeRole muda o papel de outro membro.
func (s *Service) ChangeRole(ctx context.Context, actor, tenantID, target uuid.UUID, role identity.Role) error {
	am, err := s.Authorize(ctx, actor, tenantID, authz.MembersManage)
	if err != nil {
		return err
	}
	if !role.Valid() {
		return ErrInvalidRole
	}
	if actor == target {
		return ErrSelfChange
	}
	tm, err := s.store.Member(ctx, tenantID, target)
	if err != nil {
		return err
	}
	if !authz.CanAssign(am.Role, tm.Role, role) {
		return ErrForbidden
	}
	if tm.Role == role {
		return nil
	}
	return s.store.SetRole(ctx, tenantID, target, tm.Role, role)
}

// RemoveMember remove outro membro.
func (s *Service) RemoveMember(ctx context.Context, actor, tenantID, target uuid.UUID) error {
	am, err := s.Authorize(ctx, actor, tenantID, authz.MembersManage)
	if err != nil {
		return err
	}
	if actor == target {
		return s.Leave(ctx, actor, tenantID)
	}
	tm, err := s.store.Member(ctx, tenantID, target)
	if err != nil {
		return err
	}
	// Remover = rebaixar a "nada": só quem está abaixo do ator (ou o dono).
	if !authz.CanAssign(am.Role, tm.Role, identity.RoleReader) {
		return ErrForbidden
	}
	return s.store.RemoveMember(ctx, tenantID, target)
}

// Leave: o próprio usuário sai do tenant (qualquer papel, menos o último dono).
func (s *Service) Leave(ctx context.Context, userID, tenantID uuid.UUID) error {
	if _, err := s.Authorize(ctx, userID, tenantID, authz.TenantRead); err != nil {
		return err
	}
	return s.store.RemoveMember(ctx, tenantID, userID)
}

// Suspend e Reactivate são ações da plataforma (admin da plataforma, passo
// 2b.5); não passam por papel de tenant.
func (s *Service) Suspend(ctx context.Context, tenantID uuid.UUID) error {
	return s.store.SetStatus(ctx, tenantID, StatusSuspended)
}

// Reactivate reativa um tenant suspenso.
func (s *Service) Reactivate(ctx context.Context, tenantID uuid.UUID) error {
	return s.store.SetStatus(ctx, tenantID, StatusActive)
}
