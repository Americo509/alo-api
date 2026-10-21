//go:build integration

package identity_test

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/zapgateway/zap-gateway/internal/identity"
	"github.com/zapgateway/zap-gateway/internal/storage/postgres/pgtest"
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

// Identidade é global: o repositório usa o pool da aplicação sem definir
// tenant (não há RLS no schema ident).
func repo() *identity.Repo { return identity.NewRepo(db.App) }

func newEmail() string { return uuid.NewString() + "@example.com" }

func TestUserCreateAndFetch(t *testing.T) {
	ctx := context.Background()
	r := repo()
	email := newEmail()
	u, err := r.CreateUser(ctx, email, "Fulano", false)
	if err != nil {
		t.Fatal(err)
	}
	if u.ID == uuid.Nil || u.Email != email || u.EmailVerified || u.Status != identity.StatusActive {
		t.Fatalf("usuário inesperado: %+v", u)
	}
	byID, err := r.GetUser(ctx, u.ID)
	if err != nil || byID.ID != u.ID {
		t.Fatalf("GetUser: %+v %v", byID, err)
	}
	byEmail, err := r.GetUserByEmail(ctx, "FULANO-não")
	if !errors.Is(err, identity.ErrNotFound) {
		t.Fatalf("e-mail inexistente: %+v %v", byEmail, err)
	}
	up, err := r.GetUserByEmail(ctx, email)
	if err != nil || up.ID != u.ID {
		t.Fatalf("GetUserByEmail: %v", err)
	}
}

func TestEmailUniqueCaseInsensitive(t *testing.T) {
	ctx := context.Background()
	r := repo()
	email := newEmail()
	if _, err := r.CreateUser(ctx, email, "A", false); err != nil {
		t.Fatal(err)
	}
	_, err := r.CreateUser(ctx, upper(email), "B", false)
	if !errors.Is(err, identity.ErrEmailTaken) {
		t.Fatalf("duplicado case-insensitive não barrado: %v", err)
	}
}

func TestEmailVerification(t *testing.T) {
	ctx := context.Background()
	r := repo()
	u, _ := r.CreateUser(ctx, newEmail(), "", false)
	if err := r.SetEmailVerified(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	got, _ := r.GetUser(ctx, u.ID)
	if !got.EmailVerified {
		t.Fatal("e-mail não ficou verificado")
	}
}

func TestPassword(t *testing.T) {
	ctx := context.Background()
	r := repo()
	u, _ := r.CreateUser(ctx, newEmail(), "", false)

	if _, err := r.GetPassword(ctx, u.ID); !errors.Is(err, identity.ErrNoPassword) {
		t.Fatalf("usuário novo não deveria ter senha: %v", err)
	}
	if err := r.SetPassword(ctx, u.ID, "$phc$v1"); err != nil {
		t.Fatal(err)
	}
	phc, err := r.GetPassword(ctx, u.ID)
	if err != nil || phc != "$phc$v1" {
		t.Fatalf("GetPassword: %q %v", phc, err)
	}
	if err := r.SetPassword(ctx, u.ID, "$phc$v2"); err != nil {
		t.Fatal(err)
	}
	phc, _ = r.GetPassword(ctx, u.ID)
	if phc != "$phc$v2" {
		t.Fatalf("senha não foi substituída: %q", phc)
	}
}

func TestFederatedIdentity(t *testing.T) {
	ctx := context.Background()
	r := repo()
	u, _ := r.CreateUser(ctx, newEmail(), "", true)
	const iss, sub = "https://accounts.google.com", "sub-123"

	if _, err := r.FindByIdentity(ctx, iss, sub); !errors.Is(err, identity.ErrNotFound) {
		t.Fatalf("identidade inexistente: %v", err)
	}
	if _, err := r.LinkIdentity(ctx, u.ID, iss, sub, "g@example.com"); err != nil {
		t.Fatal(err)
	}
	found, err := r.FindByIdentity(ctx, iss, sub)
	if err != nil || found.ID != u.ID {
		t.Fatalf("FindByIdentity: %+v %v", found, err)
	}
	// Mesmo (issuer, subject) não pode ir para outro usuário.
	u2, _ := r.CreateUser(ctx, newEmail(), "", true)
	if _, err := r.LinkIdentity(ctx, u2.ID, iss, sub, ""); !errors.Is(err, identity.ErrIdentityDup) {
		t.Fatalf("vínculo duplicado não barrado: %v", err)
	}
	// Mesmo subject em outro issuer é permitido.
	if _, err := r.LinkIdentity(ctx, u2.ID, "https://appleid.apple.com", sub, ""); err != nil {
		t.Fatalf("subject igual em outro issuer deveria ser permitido: %v", err)
	}
}

func TestMemberships(t *testing.T) {
	ctx := context.Background()
	r := repo()
	u, _ := r.CreateUser(ctx, newEmail(), "", true)
	tenantA, _ := db.NewTenantWithInstance(t)
	tenantB, _ := db.NewTenantWithInstance(t)

	if _, err := r.Membership(ctx, u.ID, tenantA); !errors.Is(err, identity.ErrNotFound) {
		t.Fatalf("vínculo inexistente: %v", err)
	}
	must(t, r.UpsertMembership(ctx, identity.Membership{UserID: u.ID, TenantID: tenantA, Role: identity.RoleOperator}))
	must(t, r.UpsertMembership(ctx, identity.Membership{UserID: u.ID, TenantID: tenantB, Role: identity.RoleReader}))
	// Promove no tenant A.
	must(t, r.UpsertMembership(ctx, identity.Membership{UserID: u.ID, TenantID: tenantA, Role: identity.RoleAdmin}))

	m, err := r.Membership(ctx, u.ID, tenantA)
	if err != nil || m.Role != identity.RoleAdmin {
		t.Fatalf("papel em A = %v (%v)", m.Role, err)
	}
	all, err := r.MembershipsOf(ctx, u.ID)
	if err != nil || len(all) != 2 {
		t.Fatalf("MembershipsOf = %d vínculos (%v)", len(all), err)
	}
	if err := r.UpsertMembership(ctx, identity.Membership{UserID: u.ID, TenantID: tenantA, Role: "chefe"}); err == nil {
		t.Fatal("papel inválido aceito")
	}
}

func TestTransactionRollsBack(t *testing.T) {
	ctx := context.Background()
	email := newEmail()
	err := pgx.BeginFunc(ctx, db.App, func(tx pgx.Tx) error {
		if _, err := identity.NewRepo(tx).CreateUser(ctx, email, "", false); err != nil {
			return err
		}
		return errors.New("aborta")
	})
	if err == nil {
		t.Fatal("transação deveria ter falhado")
	}
	if _, err := repo().GetUserByEmail(ctx, email); !errors.Is(err, identity.ErrNotFound) {
		t.Fatalf("usuário sobreviveu ao rollback: %v", err)
	}
}

func upper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 32
		}
	}
	return string(b)
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
