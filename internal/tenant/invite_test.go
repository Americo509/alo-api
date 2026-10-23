package tenant

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/Americo509/alo-api/internal/identity"
)

type sentMail struct{ to, token, tenant string }

type fakeMailer struct {
	sent []sentMail
	err  error
}

func (f *fakeMailer) SendInvitation(_ context.Context, to, token, tenantName string) error {
	if f.err != nil {
		return f.err
	}
	f.sent = append(f.sent, sentMail{to, token, tenantName})
	return nil
}

type invEnv struct {
	*env
	inv    *Invites
	mail   *fakeMailer
	istore *InviteMemory
}

func newInvEnv(t *testing.T) *invEnv {
	e := newEnv(t)
	m := &fakeMailer{}
	is := NewInviteMemory(e.store)
	return &invEnv{env: e, inv: NewInvites(e.svc, is, m), mail: m, istore: is}
}

func (e *invEnv) userWithEmail(email string, verified bool) uuid.UUID {
	u := identity.User{ID: uuid.New(), Email: email, EmailVerified: verified, Status: identity.StatusActive}
	e.users.m[u.ID] = u
	e.store.Profiles[u.ID] = u
	return u.ID
}

func TestInviteAndAcceptHappyPath(t *testing.T) {
	e := newInvEnv(t)
	owner := e.user(t, "dono")
	tid := e.tenantWith(t, owner, nil)

	inv, err := e.inv.Invite(ctx, owner, tid, "  Ana@Example.com ", identity.RoleOperator)
	if err != nil {
		t.Fatal(err)
	}
	if inv.Email != "ana@example.com" || len(e.mail.sent) != 1 || e.mail.sent[0].to != "ana@example.com" || e.mail.sent[0].tenant != "Clínica Aurora" {
		t.Fatalf("convite/e-mail: %+v %+v", inv, e.mail.sent)
	}
	token := e.mail.sent[0].token
	// O store guarda só o hash: o token em claro não aparece em lugar nenhum dele.
	for _, r := range e.istore.rows {
		if strings.Contains(string(r.hash), token) {
			t.Error("token em claro no store")
		}
	}
	ana := e.userWithEmail("ana@example.com", true)
	got, err := e.inv.Accept(ctx, ana, token)
	if err != nil || got.Role != identity.RoleOperator {
		t.Fatalf("accept: %+v %v", got, err)
	}
	if _, err := e.svc.Authorize(ctx, ana, tid, "messages:send"); err != nil {
		t.Errorf("novo membro sem acesso: %v", err)
	}
	if _, err := e.inv.Accept(ctx, ana, token); !errors.Is(err, ErrInvalidInvite) {
		t.Errorf("reuso do token: %v", err)
	}
}

func TestInviteRolesFollowHierarchy(t *testing.T) {
	e := newInvEnv(t)
	owner, adm, op := e.user(t, "o"), e.user(t, "a"), e.user(t, "p")
	tid := e.tenantWith(t, owner, map[uuid.UUID]identity.Role{adm: identity.RoleAdmin, op: identity.RoleOperator})
	if _, err := e.inv.Invite(ctx, adm, tid, "x@example.com", identity.RoleAdmin); !errors.Is(err, ErrForbidden) {
		t.Errorf("admin convidando admin: %v", err)
	}
	if _, err := e.inv.Invite(ctx, adm, tid, "x@example.com", identity.RoleOwner); !errors.Is(err, ErrForbidden) {
		t.Errorf("admin convidando dono: %v", err)
	}
	if _, err := e.inv.Invite(ctx, op, tid, "x@example.com", identity.RoleReader); !errors.Is(err, ErrForbidden) {
		t.Errorf("operador convidando: %v", err)
	}
	if _, err := e.inv.Invite(ctx, owner, tid, "x@example.com", "root"); !errors.Is(err, ErrInvalidRole) {
		t.Errorf("papel inválido: %v", err)
	}
	if _, err := e.inv.Invite(ctx, owner, tid, "isso-nao-e-email", identity.RoleReader); err == nil {
		t.Error("e-mail inválido aceito")
	}
	if len(e.mail.sent) != 0 {
		t.Errorf("e-mails enviados indevidamente: %d", len(e.mail.sent))
	}
}

func TestForwardedLinkDoesNotGrantAccessToAnotherPerson(t *testing.T) {
	e := newInvEnv(t)
	owner := e.user(t, "dono")
	tid := e.tenantWith(t, owner, nil)
	if _, err := e.inv.Invite(ctx, owner, tid, "ana@example.com", identity.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	token := e.mail.sent[0].token
	eve := e.userWithEmail("eve@example.com", true)
	if _, err := e.inv.Accept(ctx, eve, token); !errors.Is(err, ErrInvalidInvite) {
		t.Fatalf("outra pessoa aceitou: %v", err)
	}
	// E-mail igual mas NÃO verificado também não vale (alguém criou a conta com o e-mail alheio).
	fake := e.userWithEmail("ana@example.com", false)
	if _, err := e.inv.Accept(ctx, fake, token); !errors.Is(err, ErrInvalidInvite) {
		t.Fatalf("e-mail não verificado aceitou: %v", err)
	}
	if _, err := e.store.Member(ctx, tid, eve); !errors.Is(err, ErrNotFound) {
		t.Error("eve virou membro")
	}
	ana := e.userWithEmail("ana@example.com", true)
	if _, err := e.inv.Accept(ctx, ana, token); err != nil {
		t.Fatalf("dona legítima: %v", err)
	}
}

func TestInviteLosesValidityWhenInviterLosesPower(t *testing.T) {
	e := newInvEnv(t)
	owner, adm := e.user(t, "o"), e.user(t, "a")
	tid := e.tenantWith(t, owner, map[uuid.UUID]identity.Role{adm: identity.RoleAdmin})
	if _, err := e.inv.Invite(ctx, adm, tid, "ana@example.com", identity.RoleOperator); err != nil {
		t.Fatal(err)
	}
	token := e.mail.sent[0].token
	if err := e.svc.ChangeRole(ctx, owner, tid, adm, identity.RoleReader); err != nil {
		t.Fatal(err)
	}
	ana := e.userWithEmail("ana@example.com", true)
	if _, err := e.inv.Accept(ctx, ana, token); !errors.Is(err, ErrInvalidInvite) {
		t.Errorf("convite de quem foi rebaixado ainda vale: %v", err)
	}
	// Removido de vez: idem.
	if _, err := e.inv.Invite(ctx, owner, tid, "bia@example.com", identity.RoleReader); err != nil {
		t.Fatal(err)
	}
	if _, err := e.inv.Invite(ctx, owner, tid, "caio@example.com", identity.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	adminToken := e.mail.sent[2].token
	if err := e.svc.AddMember(ctx, owner, tid, e.user(t, "novo"), identity.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.RemoveMember(ctx, owner, tid, adm); err != nil {
		t.Fatal(err)
	}
	// O convite de admin foi feito pelo dono, que continua com poder.
	caio := e.userWithEmail("caio@example.com", true)
	if _, err := e.inv.Accept(ctx, caio, adminToken); err != nil {
		t.Errorf("convite do dono deveria valer: %v", err)
	}
}

func TestInviteMailFailureRevokes(t *testing.T) {
	e := newInvEnv(t)
	owner := e.user(t, "dono")
	tid := e.tenantWith(t, owner, nil)
	e.mail.err = errors.New("fila fora do ar")
	if _, err := e.inv.Invite(ctx, owner, tid, "ana@example.com", identity.RoleReader); err == nil {
		t.Fatal("falha de e-mail ignorada")
	}
	if p, _ := e.inv.Pending(ctx, owner, tid); len(p) != 0 {
		t.Errorf("convite órfão ficou pendente: %+v", p)
	}
}

func TestPendingAndRevokeRules(t *testing.T) {
	e := newInvEnv(t)
	owner, adm, op := e.user(t, "o"), e.user(t, "a"), e.user(t, "p")
	tid := e.tenantWith(t, owner, map[uuid.UUID]identity.Role{adm: identity.RoleAdmin, op: identity.RoleOperator})
	other := e.user(t, "z")
	otherT := e.tenantWith(t, other, nil)

	adminInv, _ := e.inv.Invite(ctx, owner, tid, "novo-admin@example.com", identity.RoleAdmin)
	readerInv, _ := e.inv.Invite(ctx, adm, tid, "leitor@example.com", identity.RoleReader)

	if _, err := e.inv.Pending(ctx, op, tid); !errors.Is(err, ErrForbidden) {
		t.Errorf("operador listando convites: %v", err)
	}
	if p, err := e.inv.Pending(ctx, adm, tid); err != nil || len(p) != 2 {
		t.Errorf("pendentes: %+v %v", p, err)
	}
	if err := e.inv.Revoke(ctx, adm, tid, adminInv.ID); !errors.Is(err, ErrForbidden) {
		t.Errorf("admin revogando convite de admin: %v", err)
	}
	if err := e.inv.Revoke(ctx, adm, tid, readerInv.ID); err != nil {
		t.Errorf("admin revogando convite de leitor: %v", err)
	}
	// Convite de outro tenant não é visível nem revogável.
	foreign, _ := e.inv.Invite(ctx, other, otherT, "x@example.com", identity.RoleReader)
	if err := e.inv.Revoke(ctx, owner, tid, foreign.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("revogou convite de outro tenant: %v", err)
	}
	if _, err := e.inv.Pending(ctx, owner, otherT); !errors.Is(err, ErrNotFound) {
		t.Errorf("listou convites de outro tenant: %v", err)
	}
}

func TestAcceptRejectsMalformedTokens(t *testing.T) {
	e := newInvEnv(t)
	u := e.userWithEmail("ana@example.com", true)
	for _, tok := range []string{"", "curto", strings.Repeat("A", 200), "!!!!", strings.Repeat("A", 43)} {
		if _, err := e.inv.Accept(ctx, u, tok); !errors.Is(err, ErrInvalidInvite) {
			t.Errorf("token %q: %v", tok, err)
		}
	}
}
