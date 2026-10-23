//go:build integration

package tenant_test

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"

	"github.com/Americo509/alo-api/internal/identity"
	"github.com/Americo509/alo-api/internal/storage/postgres/pgtest"
	"github.com/Americo509/alo-api/internal/tenant"
	"github.com/Americo509/alo-api/internal/tenant/storetest"
)

var db *pgtest.DB

func TestMain(m *testing.M) {
	var stop func()
	var err error
	db, stop, err = pgtest.Start(context.Background())
	if err != nil {
		panic(err)
	}
	code := m.Run()
	stop()
	os.Exit(code)
}

// O Postgres tem que se comportar exatamente como a versão em memória, com RLS
// ativo (a aplicação usa o papel app_rw, sem BYPASSRLS).
func TestPGStoreContract(t *testing.T) {
	storetest.Run(t, func(t *testing.T) (tenant.Store, func() uuid.UUID) {
		newUser := func() uuid.UUID {
			u, err := identity.NewRepo(db.Owner).CreateUser(context.Background(), uuid.NewString()+"@example.com", "", true)
			if err != nil {
				t.Fatal(err)
			}
			return u.ID
		}
		return tenant.NewPG(db.App), newUser
	})
}

func TestPGTenantRowsAreInvisibleAcrossTenants(t *testing.T) {
	ctx := context.Background()
	s := tenant.NewPG(db.App)
	repo := identity.NewRepo(db.Owner)
	ua, _ := repo.CreateUser(ctx, uuid.NewString()+"@example.com", "", true)
	ub, _ := repo.CreateUser(ctx, uuid.NewString()+"@example.com", "", true)
	mk := func(owner uuid.UUID) uuid.UUID {
		tn := tenant.Tenant{ID: uuid.New(), Name: "T", Status: tenant.StatusActive, CreatedBy: owner}
		if err := s.Create(ctx, tn); err != nil {
			t.Fatal(err)
		}
		return tn.ID
	}
	ta, tb := mk(ua.ID), mk(ub.ID)

	// Sem contexto de tenant, a aplicação não enxerga nenhuma linha de core.tenants.
	var n int
	if err := db.App.QueryRow(ctx, `SELECT count(*) FROM core.tenants`).Scan(&n); err == nil {
		t.Fatalf("consulta sem tenant deveria falhar, devolveu %d", n)
	}
	// Renomear B não toca em A: cada operação roda no contexto do próprio tenant.
	if err := s.Rename(ctx, tb, "x"); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Get(ctx, ta); got.Name != "T" {
		t.Errorf("tenant A foi alterado: %q", got.Name)
	}
}
