//go:build integration

package passkey_test

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/Americo509/alo-api/internal/identity"
	"github.com/Americo509/alo-api/internal/identity/passkey"
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

func newUser(t *testing.T) uuid.UUID {
	t.Helper()
	u, err := identity.NewRepo(db.App).CreateUser(context.Background(), uuid.NewString()+"@example.com", "", true)
	if err != nil {
		t.Fatal(err)
	}
	return u.ID
}

func newCred(t *testing.T) webauthn.Credential {
	t.Helper()
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		t.Fatal(err)
	}
	return webauthn.Credential{ID: id, PublicKey: []byte{1, 2, 3, 4}, AttestationType: "none"}
}

func TestPGCredentialsLifecycle(t *testing.T) {
	ctx := context.Background()
	s := passkey.NewPGCredentials(db.App)
	uid := newUser(t)
	c := newCred(t)
	now := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)

	if err := s.Add(ctx, uid, c, "notebook", now); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(ctx, uid, c, "de novo", now); !errors.Is(err, passkey.ErrDuplicate) {
		t.Fatalf("credencial duplicada aceita: %v", err)
	}

	list, err := s.ListByUser(ctx, uid)
	if err != nil || len(list) != 1 || list[0].Label != "notebook" {
		t.Fatalf("ListByUser = %+v, %v", list, err)
	}
	got, err := s.Find(ctx, c.ID)
	if err != nil || got.UserID != uid || string(got.Credential.PublicKey) != string(c.PublicKey) {
		t.Fatalf("Find = %+v, %v", got, err)
	}

	// Atualização preserva o contador no JSON.
	c.Authenticator.SignCount = 42
	if err := s.Update(ctx, c.ID, c, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	got, _ = s.Find(ctx, c.ID)
	if got.Credential.Authenticator.SignCount != 42 || got.LastUsedAt.IsZero() {
		t.Fatalf("Update não persistiu: %+v", got)
	}

	if _, err := s.Find(ctx, []byte("nao-existe")); !errors.Is(err, passkey.ErrNotFound) {
		t.Fatalf("Find inexistente: %v", err)
	}
}

func TestPGCredentialsDeleteOnlyByOwner(t *testing.T) {
	ctx := context.Background()
	s := passkey.NewPGCredentials(db.App)
	owner, other := newUser(t), newUser(t)
	c := newCred(t)
	if err := s.Add(ctx, owner, c, "", time.Now()); err != nil { //nolint:forbidigo // teste de integração
		t.Fatal(err)
	}
	if err := s.Delete(ctx, other, c.ID); !errors.Is(err, passkey.ErrNotFound) {
		t.Fatalf("outro usuário apagou a passkey: %v", err)
	}
	if err := s.Delete(ctx, owner, c.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Find(ctx, c.ID); !errors.Is(err, passkey.ErrNotFound) {
		t.Fatal("passkey ainda existe após Delete")
	}
}

// Ao apagar o usuário, as passkeys somem junto (ON DELETE CASCADE) — direito
// de exclusão da LGPD.
func TestPGCredentialsCascadeOnUserDelete(t *testing.T) {
	ctx := context.Background()
	s := passkey.NewPGCredentials(db.App)
	uid := newUser(t)
	c := newCred(t)
	if err := s.Add(ctx, uid, c, "", time.Now()); err != nil { //nolint:forbidigo // teste de integração
		t.Fatal(err)
	}
	if _, err := db.App.Exec(ctx, `DELETE FROM ident.users WHERE id = $1`, uid); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Find(ctx, c.ID); !errors.Is(err, passkey.ErrNotFound) {
		t.Fatalf("passkey sobreviveu à exclusão do usuário: %v", err)
	}
}
