// Package storetest é o teste de contrato de tenant.Store: roda igual contra a
// versão em memória e contra o Postgres, garantindo que as duas se comportam
// do mesmo jeito (inclusive a invariante "ao menos um dono").
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

// Factory entrega um Store limpo e uma função que cria usuários existentes.
type Factory func(t *testing.T) (s tenant.Store, newUser func() uuid.UUID)

func create(t *testing.T, s tenant.Store, owner uuid.UUID) tenant.Tenant {
	t.Helper()
	tn := tenant.Tenant{ID: uuid.New(), Name: "T", Status: tenant.StatusActive, CreatedBy: owner, CreatedAt: time.Unix(1_700_000_000, 0).UTC()}
	if err := s.Create(context.Background(), tn); err != nil {
		t.Fatal(err)
	}
	return tn
}

// Run executa o contrato.
func Run(t *testing.T, f Factory) {
	ctx := context.Background()

	t.Run("criar", func(t *testing.T) {
		s, nu := f(t)
		u := nu()
		tn := create(t, s, u)
		got, err := s.Get(ctx, tn.ID)
		if err != nil || got.Name != "T" || got.Status != tenant.StatusActive {
			t.Fatalf("get: %+v %v", got, err)
		}
		m, err := s.Member(ctx, tn.ID, u)
		if err != nil || m.Role != identity.RoleOwner {
			t.Fatalf("dono: %+v %v", m, err)
		}
		if n, _ := s.OwnedCount(ctx, u); n != 1 {
			t.Errorf("OwnedCount=%d", n)
		}
		if _, err := s.Get(ctx, uuid.New()); !errors.Is(err, tenant.ErrNotFound) {
			t.Errorf("inexistente: %v", err)
		}
	})

	t.Run("membros e papéis", func(t *testing.T) {
		s, nu := f(t)
		o, a := nu(), nu()
		tn := create(t, s, o)
		if err := s.AddMember(ctx, tn.ID, a, identity.RoleOperator); err != nil {
			t.Fatal(err)
		}
		if err := s.AddMember(ctx, tn.ID, a, identity.RoleReader); !errors.Is(err, tenant.ErrAlreadyMember) {
			t.Errorf("duplicado: %v", err)
		}
		if err := s.SetRole(ctx, tn.ID, a, identity.RoleAdmin, identity.RoleReader); !errors.Is(err, tenant.ErrStale) {
			t.Errorf("papel esperado errado deveria dar ErrStale: %v", err)
		}
		if err := s.SetRole(ctx, tn.ID, a, identity.RoleOperator, identity.RoleAdmin); err != nil {
			t.Fatal(err)
		}
		if m, _ := s.Member(ctx, tn.ID, a); m.Role != identity.RoleAdmin {
			t.Errorf("papel: %s", m.Role)
		}
		ms, _ := s.Members(ctx, tn.ID)
		if len(ms) != 2 {
			t.Errorf("membros: %d", len(ms))
		}
		mine, _ := s.MembershipsOf(ctx, a)
		if len(mine) != 1 || mine[0].Tenant.ID != tn.ID || mine[0].Role != identity.RoleAdmin {
			t.Errorf("MembershipsOf: %+v", mine)
		}
		if err := s.RemoveMember(ctx, tn.ID, a); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Member(ctx, tn.ID, a); !errors.Is(err, tenant.ErrNotFound) {
			t.Errorf("removido ainda existe: %v", err)
		}
		if err := s.RemoveMember(ctx, tn.ID, a); !errors.Is(err, tenant.ErrNotFound) {
			t.Errorf("remover duas vezes: %v", err)
		}
	})

	t.Run("nunca zero donos", func(t *testing.T) {
		s, nu := f(t)
		o, p := nu(), nu()
		tn := create(t, s, o)
		if err := s.SetRole(ctx, tn.ID, o, identity.RoleOwner, identity.RoleAdmin); !errors.Is(err, tenant.ErrLastOwner) {
			t.Errorf("rebaixar último dono: %v", err)
		}
		if err := s.RemoveMember(ctx, tn.ID, o); !errors.Is(err, tenant.ErrLastOwner) {
			t.Errorf("remover último dono: %v", err)
		}
		if err := s.AddMember(ctx, tn.ID, p, identity.RoleOwner); err != nil {
			t.Fatal(err)
		}
		if err := s.SetRole(ctx, tn.ID, o, identity.RoleOwner, identity.RoleAdmin); err != nil {
			t.Errorf("com 2 donos pode rebaixar: %v", err)
		}
		// Agora p é o único dono de novo.
		if err := s.RemoveMember(ctx, tn.ID, p); !errors.Is(err, tenant.ErrLastOwner) {
			t.Errorf("remover o novo último dono: %v", err)
		}
	})

	t.Run("rebaixamentos concorrentes mantêm um dono", func(t *testing.T) {
		for i := 0; i < 20; i++ {
			s, nu := f(t)
			a, b := nu(), nu()
			tn := create(t, s, a)
			if err := s.AddMember(ctx, tn.ID, b, identity.RoleOwner); err != nil {
				t.Fatal(err)
			}
			var wg sync.WaitGroup
			wg.Add(2)
			go func() { defer wg.Done(); _ = s.SetRole(ctx, tn.ID, a, identity.RoleOwner, identity.RoleReader) }()
			go func() { defer wg.Done(); _ = s.SetRole(ctx, tn.ID, b, identity.RoleOwner, identity.RoleReader) }()
			wg.Wait()
			ms, _ := s.Members(ctx, tn.ID)
			owners := 0
			for _, m := range ms {
				if m.Role == identity.RoleOwner {
					owners++
				}
			}
			if owners != 1 {
				t.Fatalf("rodada %d: %d donos (esperado exatamente 1)", i, owners)
			}
		}
	})

	t.Run("status e nome", func(t *testing.T) {
		s, nu := f(t)
		tn := create(t, s, nu())
		if err := s.Rename(ctx, tn.ID, "Outro"); err != nil {
			t.Fatal(err)
		}
		if err := s.SetStatus(ctx, tn.ID, tenant.StatusSuspended); err != nil {
			t.Fatal(err)
		}
		got, _ := s.Get(ctx, tn.ID)
		if got.Name != "Outro" || got.Status != tenant.StatusSuspended {
			t.Errorf("%+v", got)
		}
		if err := s.Rename(ctx, uuid.New(), "x"); !errors.Is(err, tenant.ErrNotFound) {
			t.Errorf("renomear inexistente: %v", err)
		}
	})
}
