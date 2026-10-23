//go:build integration

package oidclogin_test

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/google/uuid"

	"github.com/Americo509/alo-api/internal/identity"
	"github.com/Americo509/alo-api/internal/identity/oidclogin"
	"github.com/Americo509/alo-api/internal/storage/postgres/pgtest"
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

func newAccounts() *oidclogin.PGAccounts {
	return oidclogin.NewPGAccounts(db.App, identity.NewRepo(db.App))
}

func email() string { return uuid.NewString() + "@example.com" }

const iss = "https://accounts.google.com"

// Criar usuário + vínculo é atômico: se o vínculo falha, o usuário não fica.
func TestPGCreateWithIdentityIsAtomic(t *testing.T) {
	ctx := context.Background()
	a := newAccounts()
	sub := uuid.NewString()

	u, err := a.CreateWithIdentity(ctx, email(), "Ana", true, iss, sub)
	if err != nil {
		t.Fatal(err)
	}
	found, err := a.FindByIdentity(ctx, iss, sub)
	if err != nil || found.ID != u.ID {
		t.Fatalf("FindByIdentity = %+v, %v", found, err)
	}

	// Mesmo (issuer, subject) com e-mail novo: o vínculo falha e o usuário NÃO é criado.
	orphan := email()
	if _, err := a.CreateWithIdentity(ctx, orphan, "", true, iss, sub); !errors.Is(err, identity.ErrIdentityDup) {
		t.Fatalf("vínculo duplicado: %v", err)
	}
	if _, err := a.GetUserByEmail(ctx, orphan); !errors.Is(err, identity.ErrNotFound) {
		t.Fatalf("usuário ficou órfão após falha do vínculo: %v", err)
	}
}

func TestPGCreateWithIdentityEmailTaken(t *testing.T) {
	ctx := context.Background()
	a := newAccounts()
	e := email()
	if _, err := a.CreateWithIdentity(ctx, e, "", true, iss, uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	if _, err := a.CreateWithIdentity(ctx, e, "", true, iss, uuid.NewString()); !errors.Is(err, identity.ErrEmailTaken) {
		t.Fatalf("e-mail duplicado: %v", err)
	}
}

func TestPGLinkIdentity(t *testing.T) {
	ctx := context.Background()
	a := newAccounts()
	u1, _ := a.CreateWithIdentity(ctx, email(), "", true, iss, uuid.NewString())
	u2, _ := a.CreateWithIdentity(ctx, email(), "", true, iss, uuid.NewString())
	sub := uuid.NewString()

	if err := a.LinkIdentity(ctx, u1.ID, "https://appleid.apple.com", sub, ""); err != nil {
		t.Fatal(err)
	}
	if err := a.LinkIdentity(ctx, u2.ID, "https://appleid.apple.com", sub, ""); !errors.Is(err, identity.ErrIdentityDup) {
		t.Fatalf("identidade vinculada a dois usuários: %v", err)
	}
}
