package storetest

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Americo509/alo-api/internal/identity"
	"github.com/Americo509/alo-api/internal/tenant"
)

// InviteFactory entrega os dois stores ligados ao mesmo banco, e um criador de
// usuários (com o e-mail dado).
type InviteFactory func(t *testing.T) (tenant.Store, tenant.InviteStore, func(email string) uuid.UUID)

var t0 = time.Unix(1_700_000_000, 0).UTC()

func invite(tid, by uuid.UUID, email string, role identity.Role) (tenant.Invitation, []byte) {
	h := make([]byte, 32)
	copy(h, uuid.NewString())
	copy(h[16:], uuid.NewString())
	return tenant.Invitation{
		ID: uuid.New(), TenantID: tid, Email: email, Role: role, InvitedBy: by,
		CreatedAt: t0, ExpiresAt: t0.Add(tenant.InvitationTTL),
	}, h
}

// RunInvites executa o contrato dos convites.
func RunInvites(t *testing.T, f InviteFactory) {
	ctx := context.Background()
	setup := func(t *testing.T) (tenant.Store, tenant.InviteStore, func(string) uuid.UUID, tenant.Tenant, uuid.UUID) {
		ts, is, nu := f(t)
		owner := nu("dono@example.com")
		return ts, is, nu, create(t, ts, owner), owner
	}

	t.Run("aceitar cria o vínculo uma única vez", func(t *testing.T) {
		ts, is, nu, tn, owner := setup(t)
		inv, h := invite(tn.ID, owner, "ana@example.com", identity.RoleOperator)
		if err := is.Create(ctx, inv, h, t0); err != nil {
			t.Fatal(err)
		}
		ana := nu("ana@example.com")
		got, err := is.Accept(ctx, h, ana, "ANA@example.com", t0.Add(time.Hour))
		if err != nil || got.Role != identity.RoleOperator {
			t.Fatalf("accept: %+v %v", got, err)
		}
		if m, err := ts.Member(ctx, tn.ID, ana); err != nil || m.Role != identity.RoleOperator {
			t.Fatalf("vínculo: %+v %v", m, err)
		}
		if _, err := is.Accept(ctx, h, ana, "ana@example.com", t0.Add(time.Hour)); !errors.Is(err, tenant.ErrInvalidInvite) {
			t.Errorf("segundo aceite: %v", err)
		}
		if p, _ := is.Pending(ctx, tn.ID, t0); len(p) != 0 {
			t.Errorf("aceito ainda pendente: %+v", p)
		}
	})

	t.Run("e-mail errado, expirado, revogado e desconhecido", func(t *testing.T) {
		_, is, nu, tn, owner := setup(t)
		inv, h := invite(tn.ID, owner, "ana@example.com", identity.RoleReader)
		if err := is.Create(ctx, inv, h, t0); err != nil {
			t.Fatal(err)
		}
		eve := nu("eve@example.com")
		if _, err := is.Accept(ctx, h, eve, "eve@example.com", t0); !errors.Is(err, tenant.ErrInvalidInvite) {
			t.Errorf("e-mail de outra pessoa: %v", err)
		}
		if _, err := is.Accept(ctx, h, eve, "ana@example.com", t0.Add(tenant.InvitationTTL)); !errors.Is(err, tenant.ErrInvalidInvite) {
			t.Errorf("expirado: %v", err)
		}
		if _, err := is.Accept(ctx, make([]byte, 32), eve, "ana@example.com", t0); !errors.Is(err, tenant.ErrInvalidInvite) {
			t.Errorf("desconhecido: %v", err)
		}
		if err := is.Revoke(ctx, tn.ID, inv.ID, t0); err != nil {
			t.Fatal(err)
		}
		if _, err := is.Accept(ctx, h, nu("ana@example.com"), "ana@example.com", t0); !errors.Is(err, tenant.ErrInvalidInvite) {
			t.Errorf("revogado: %v", err)
		}
		if err := is.Revoke(ctx, tn.ID, inv.ID, t0); !errors.Is(err, tenant.ErrNotFound) {
			t.Errorf("revogar duas vezes: %v", err)
		}
	})

	t.Run("quem já é membro não consome o convite", func(t *testing.T) {
		_, is, _, tn, owner := setup(t)
		inv, h := invite(tn.ID, owner, "dono@example.com", identity.RoleReader)
		if err := is.Create(ctx, inv, h, t0); err != nil {
			t.Fatal(err)
		}
		if _, err := is.Accept(ctx, h, owner, "dono@example.com", t0); !errors.Is(err, tenant.ErrAlreadyMember) {
			t.Errorf("já membro: %v", err)
		}
		if p, _ := is.Pending(ctx, tn.ID, t0); len(p) != 1 {
			t.Errorf("o convite foi consumido: %d pendentes", len(p))
		}
	})

	t.Run("tenant suspenso não aceita convite", func(t *testing.T) {
		ts, is, nu, tn, owner := setup(t)
		inv, h := invite(tn.ID, owner, "ana@example.com", identity.RoleReader)
		if err := is.Create(ctx, inv, h, t0); err != nil {
			t.Fatal(err)
		}
		if err := ts.SetStatus(ctx, tn.ID, tenant.StatusSuspended); err != nil {
			t.Fatal(err)
		}
		if _, err := is.Accept(ctx, h, nu("ana@example.com"), "ana@example.com", t0); !errors.Is(err, tenant.ErrInvalidInvite) {
			t.Errorf("tenant suspenso: %v", err)
		}
	})

	t.Run("novo convite substitui o pendente do mesmo e-mail", func(t *testing.T) {
		_, is, nu, tn, owner := setup(t)
		a, ha := invite(tn.ID, owner, "ana@example.com", identity.RoleReader)
		b, hb := invite(tn.ID, owner, "ANA@example.com", identity.RoleAdmin)
		if err := is.Create(ctx, a, ha, t0); err != nil {
			t.Fatal(err)
		}
		if err := is.Create(ctx, b, hb, t0); err != nil {
			t.Fatal(err)
		}
		p, _ := is.Pending(ctx, tn.ID, t0)
		if len(p) != 1 || p[0].ID != b.ID {
			t.Fatalf("pendentes: %+v", p)
		}
		ana := nu("ana@example.com")
		if _, err := is.Accept(ctx, ha, ana, "ana@example.com", t0); !errors.Is(err, tenant.ErrInvalidInvite) {
			t.Errorf("convite antigo ainda vale: %v", err)
		}
		if got, err := is.Accept(ctx, hb, ana, "ana@example.com", t0); err != nil || got.Role != identity.RoleAdmin {
			t.Errorf("convite novo: %+v %v", got, err)
		}
	})

	t.Run("limite de pendentes", func(t *testing.T) {
		_, is, _, tn, owner := setup(t)
		for i := 0; i < tenant.MaxPendingInvites; i++ {
			inv, h := invite(tn.ID, owner, uuid.NewString()+"@example.com", identity.RoleReader)
			if err := is.Create(ctx, inv, h, t0); err != nil {
				t.Fatalf("convite %d: %v", i, err)
			}
		}
		inv, h := invite(tn.ID, owner, "extra@example.com", identity.RoleReader)
		if err := is.Create(ctx, inv, h, t0); !errors.Is(err, tenant.ErrTooManyInvites) {
			t.Errorf("acima do limite: %v", err)
		}
		// Convites expirados não contam.
		if err := is.Create(ctx, inv, h, t0.Add(tenant.InvitationTTL+time.Hour)); err != nil {
			t.Errorf("expirados não deveriam contar: %v", err)
		}
	})

	t.Run("aceites concorrentes: só um vence", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			ts, is, nu, tn, owner := setup(t)
			inv, h := invite(tn.ID, owner, "ana@example.com", identity.RoleReader)
			if err := is.Create(ctx, inv, h, t0); err != nil {
				t.Fatal(err)
			}
			u1, u2 := nu("ana@example.com"), nu("ana@example.com")
			var wg sync.WaitGroup
			var ok int
			var mu sync.Mutex
			for _, u := range []uuid.UUID{u1, u2} {
				wg.Add(1)
				go func() {
					defer wg.Done()
					if _, err := is.Accept(ctx, h, u, "ana@example.com", t0); err == nil {
						mu.Lock()
						ok++
						mu.Unlock()
					}
				}()
			}
			wg.Wait()
			ms, _ := ts.Members(ctx, tn.ID)
			if ok != 1 || len(ms) != 2 {
				t.Fatalf("rodada %d: %d aceites, %d membros (esperado 1 e 2)", i, ok, len(ms))
			}
		}
	})
}
