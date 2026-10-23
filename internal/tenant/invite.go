package tenant

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/Americo509/alo-api/internal/authz"
	"github.com/Americo509/alo-api/internal/identity"
)

// Convites: um admin convida um e-mail para um papel; o token vai por e-mail e
// só vale para quem tem aquele e-mail verificado.

// InvitationTTL é a validade do convite (acompanha mailer.InvitationValidity).
const InvitationTTL = 7 * 24 * time.Hour

// MaxPendingInvites limita convites pendentes por tenant (anti-abuso de e-mail).
const MaxPendingInvites = 50

var (
	// ErrInvalidInvite cobre token inexistente, expirado, revogado, já usado ou
	// de outro e-mail. Mensagem única: não revela qual foi o caso.
	ErrInvalidInvite = errors.New("tenant: convite inválido ou expirado")
	// ErrTooManyInvites: muitos convites pendentes no tenant.
	ErrTooManyInvites = errors.New("tenant: convites pendentes demais")
)

// Invitation é um convite.
type Invitation struct {
	ID        uuid.UUID
	TenantID  uuid.UUID
	Email     string
	Role      identity.Role
	InvitedBy uuid.UUID
	CreatedAt time.Time
	ExpiresAt time.Time
}

// InviteStore é a persistência de convites.
type InviteStore interface {
	// Create revoga qualquer convite pendente do mesmo e-mail no tenant e grava
	// o novo, atomicamente. ErrTooManyInvites se passar do limite.
	Create(ctx context.Context, inv Invitation, tokenHash []byte, now time.Time) error
	// Find devolve o convite pelo hash do token (qualquer estado), ou ErrInvalidInvite.
	Find(ctx context.Context, tokenHash []byte) (Invitation, error)
	// Accept consome o convite e cria o vínculo, atomicamente: só se estiver
	// pendente, não expirado, o tenant ativo e o e-mail for o do convite.
	// Quem já é membro recebe ErrAlreadyMember e o convite NÃO é consumido.
	Accept(ctx context.Context, tokenHash []byte, userID uuid.UUID, email string, now time.Time) (Invitation, error)
	// Pending lista os convites pendentes e não expirados.
	Pending(ctx context.Context, tenantID uuid.UUID, now time.Time) ([]Invitation, error)
	Revoke(ctx context.Context, tenantID, id uuid.UUID, now time.Time) error
}

// Mailer manda o e-mail de convite (mailer.OutboxMailer satisfaz).
type Mailer interface {
	SendInvitation(ctx context.Context, to, token, tenantName string) error
}

// Invites é o serviço de convites.
type Invites struct {
	svc    *Service
	store  InviteStore
	mailer Mailer
	rand   func([]byte) (int, error)
}

// NewInvites cria o serviço sobre o Service de tenants.
func NewInvites(svc *Service, store InviteStore, m Mailer) *Invites {
	return &Invites{svc: svc, store: store, mailer: m, rand: rand.Read}
}

func hashToken(raw []byte) []byte { h := sha256.Sum256(raw); return h[:] }

var b64 = base64.RawURLEncoding

// Invite convida o e-mail para o papel. Não revela se o e-mail já tem conta.
func (i *Invites) Invite(ctx context.Context, actor, tenantID uuid.UUID, rawEmail string, role identity.Role) (Invitation, error) {
	am, err := i.svc.Authorize(ctx, actor, tenantID, authz.MembersManage)
	if err != nil {
		return Invitation{}, err
	}
	if !role.Valid() {
		return Invitation{}, ErrInvalidRole
	}
	if !authz.CanAssign(am.Role, "", role) {
		return Invitation{}, ErrForbidden
	}
	email, err := identity.NormalizeEmail(rawEmail)
	if err != nil {
		return Invitation{}, err
	}
	t, err := i.svc.store.Get(ctx, tenantID)
	if err != nil {
		return Invitation{}, err
	}
	raw := make([]byte, 32)
	if _, err := i.rand(raw); err != nil {
		return Invitation{}, err
	}
	now := i.svc.clock.Now()
	inv := Invitation{
		ID: i.svc.newID(), TenantID: tenantID, Email: email, Role: role,
		InvitedBy: actor, CreatedAt: now, ExpiresAt: now.Add(InvitationTTL),
	}
	if err := i.store.Create(ctx, inv, hashToken(raw), now); err != nil {
		return Invitation{}, err
	}
	if err := i.mailer.SendInvitation(ctx, email, b64.EncodeToString(raw), t.Name); err != nil {
		// Sem e-mail o convite não serve: revoga para não ficar pendente à toa.
		_ = i.store.Revoke(ctx, tenantID, inv.ID, now)
		return Invitation{}, err
	}
	return inv, nil
}

// Accept aceita o convite em nome do usuário logado.
func (i *Invites) Accept(ctx context.Context, userID uuid.UUID, token string) (Invitation, error) {
	raw, err := b64.DecodeString(token)
	if err != nil || len(raw) != 32 {
		return Invitation{}, ErrInvalidInvite
	}
	hash := hashToken(raw)
	u, err := i.svc.users.GetUser(ctx, userID)
	if err != nil || !u.CanLogIn() || !u.EmailVerified {
		return Invitation{}, ErrInvalidInvite
	}
	inv, err := i.store.Find(ctx, hash)
	if err != nil {
		return Invitation{}, err
	}
	// Quem convidou ainda precisa poder conceder esse papel: se foi rebaixado
	// ou removido depois de convidar, o convite perde a validade.
	im, err := i.svc.store.Member(ctx, inv.TenantID, inv.InvitedBy)
	if err != nil || !authz.CanAssign(im.Role, "", inv.Role) {
		return Invitation{}, ErrInvalidInvite
	}
	return i.store.Accept(ctx, hash, userID, u.Email, i.svc.clock.Now())
}

// Pending lista os convites pendentes (para o painel).
func (i *Invites) Pending(ctx context.Context, actor, tenantID uuid.UUID) ([]Invitation, error) {
	if _, err := i.svc.Authorize(ctx, actor, tenantID, authz.MembersManage); err != nil {
		return nil, err
	}
	return i.store.Pending(ctx, tenantID, i.svc.clock.Now())
}

// Revoke cancela um convite pendente. Um admin não cancela convite de papel
// acima do dele.
func (i *Invites) Revoke(ctx context.Context, actor, tenantID, id uuid.UUID) error {
	am, err := i.svc.Authorize(ctx, actor, tenantID, authz.MembersManage)
	if err != nil {
		return err
	}
	pend, err := i.store.Pending(ctx, tenantID, i.svc.clock.Now())
	if err != nil {
		return err
	}
	for _, p := range pend {
		if p.ID != id {
			continue
		}
		if !authz.CanAssign(am.Role, "", p.Role) {
			return ErrForbidden
		}
		return i.store.Revoke(ctx, tenantID, id, i.svc.clock.Now())
	}
	return ErrNotFound
}
