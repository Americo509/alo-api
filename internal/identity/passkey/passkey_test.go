package passkey

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Americo509/alo-api/internal/clock"
	"github.com/Americo509/alo-api/internal/identity"
	"github.com/Americo509/alo-api/internal/identity/ephemeral"
)

const (
	rpID   = "app.example.com"
	origin = "https://app.example.com"
)

var (
	ctx = context.Background()
	t0  = time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
)

type fakeUsers struct{ m map[uuid.UUID]identity.User }

func (f *fakeUsers) GetUser(_ context.Context, id uuid.UUID) (identity.User, error) {
	u, ok := f.m[id]
	if !ok {
		return identity.User{}, identity.ErrNotFound
	}
	return u, nil
}

type env struct {
	svc   *Service
	creds *MemoryCredentials
	users *fakeUsers
	clk   *clock.Fake
}

func newEnv(t *testing.T) *env {
	t.Helper()
	clk := clock.NewFake(t0)
	creds := NewMemoryCredentials()
	users := &fakeUsers{m: map[uuid.UUID]identity.User{}}
	svc, err := New(Config{RPID: rpID, RPDisplayName: "Alô API", RPOrigins: []string{origin}},
		creds, users, ephemeral.NewMemory(clk), clk, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &env{svc: svc, creds: creds, users: users, clk: clk}
}

func (e *env) newUser(email string) identity.User {
	u := identity.User{ID: uuid.New(), Email: email, EmailVerified: true, Status: identity.StatusActive}
	e.users.m[u.ID] = u
	return u
}

// enroll cadastra uma passkey nova para o usuário e devolve o autenticador.
func (e *env) enroll(t *testing.T, u identity.User) *softAuth {
	t.Helper()
	a := newSoftAuth(t, rpID, origin)
	opts, token, err := e.svc.BeginRegistration(ctx, u.ID)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	if err := e.svc.FinishRegistration(ctx, u.ID, token, post(t, a.register(opts)), "meu notebook"); err != nil {
		t.Fatalf("FinishRegistration: %v", err)
	}
	return a
}

func TestRegisterAndLogin(t *testing.T) {
	e := newEnv(t)
	u := e.newUser("ana@example.com")
	a := e.enroll(t, u)

	list, err := e.svc.List(ctx, u.ID)
	if err != nil || len(list) != 1 || list[0].Label != "meu notebook" {
		t.Fatalf("List = %+v, %v", list, err)
	}

	opts, token, err := e.svc.BeginLogin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got, err := e.svc.FinishLogin(ctx, token, post(t, a.assert(opts, 1)))
	if err != nil {
		t.Fatalf("FinishLogin: %v", err)
	}
	if got.ID != u.ID {
		t.Fatalf("autenticou %v, quer %v", got.ID, u.ID)
	}
	after, _ := e.creds.Find(ctx, a.credID)
	if after.Credential.Authenticator.SignCount != 1 || after.LastUsedAt.IsZero() {
		t.Fatalf("contador/uso não atualizados: %+v", after)
	}
}

func TestLoginChallengeIsSingleUse(t *testing.T) {
	e := newEnv(t)
	u := e.newUser("ana@example.com")
	a := e.enroll(t, u)
	opts, token, _ := e.svc.BeginLogin(ctx)
	body := a.assert(opts, 1)
	if _, err := e.svc.FinishLogin(ctx, token, post(t, body)); err != nil {
		t.Fatal(err)
	}
	// Repetir exatamente a mesma resposta (replay) tem de falhar.
	if _, err := e.svc.FinishLogin(ctx, token, post(t, body)); !errors.Is(err, ErrCeremony) {
		t.Fatalf("replay aceito: %v", err)
	}
}

func TestCeremonyExpires(t *testing.T) {
	e := newEnv(t)
	u := e.newUser("ana@example.com")
	a := e.enroll(t, u)
	opts, token, _ := e.svc.BeginLogin(ctx)
	e.clk.Advance(6 * time.Minute)
	if _, err := e.svc.FinishLogin(ctx, token, post(t, a.assert(opts, 1))); !errors.Is(err, ErrCeremony) {
		t.Fatalf("cerimônia expirada aceita: %v", err)
	}
}

func TestWrongOriginRejected(t *testing.T) {
	e := newEnv(t)
	u := e.newUser("ana@example.com")
	a := e.enroll(t, u)
	opts, token, _ := e.svc.BeginLogin(ctx)
	a.origin = "https://phishing.example.net" // site falso pedindo a assinatura
	if _, err := e.svc.FinishLogin(ctx, token, post(t, a.assert(opts, 1))); err == nil {
		t.Fatal("login com origem diferente foi aceito (phishing)")
	}
}

func TestWrongRPIDRejected(t *testing.T) {
	e := newEnv(t)
	u := e.newUser("ana@example.com")
	a := e.enroll(t, u)
	opts, token, _ := e.svc.BeginLogin(ctx)
	a.rpID = "outro.example.com"
	if _, err := e.svc.FinishLogin(ctx, token, post(t, a.assert(opts, 1))); err == nil {
		t.Fatal("login com RP ID diferente foi aceito")
	}
}

func TestCloneDetection(t *testing.T) {
	e := newEnv(t)
	u := e.newUser("ana@example.com")
	a := e.enroll(t, u)

	opts, token, _ := e.svc.BeginLogin(ctx)
	if _, err := e.svc.FinishLogin(ctx, token, post(t, a.assert(opts, 5))); err != nil {
		t.Fatal(err)
	}
	// Um clone usa um contador menor (ou igual): tem de ser recusado e marcado.
	opts, token, _ = e.svc.BeginLogin(ctx)
	_, err := e.svc.FinishLogin(ctx, token, post(t, a.assert(opts, 3)))
	if !errors.Is(err, ErrCloned) {
		t.Fatalf("clone não detectado: %v", err)
	}
	st, _ := e.creds.Find(ctx, a.credID)
	if !st.Credential.Authenticator.CloneWarning {
		t.Fatal("credencial não foi marcada como clone suspeito")
	}
}

func TestUserVerificationRequired(t *testing.T) {
	e := newEnv(t)
	u := e.newUser("ana@example.com")

	// Registro sem verificação do usuário (sem biometria/PIN) é recusado.
	weak := newSoftAuth(t, rpID, origin)
	weak.userVerified = false
	opts, token, _ := e.svc.BeginRegistration(ctx, u.ID)
	if err := e.svc.FinishRegistration(ctx, u.ID, token, post(t, weak.register(opts)), "x"); err == nil {
		t.Fatal("registro sem verificação do usuário foi aceito")
	}

	// Login sem verificação do usuário também.
	a := e.enroll(t, u)
	a.userVerified = false
	opts2, token2, _ := e.svc.BeginLogin(ctx)
	if _, err := e.svc.FinishLogin(ctx, token2, post(t, a.assert(opts2, 1))); err == nil {
		t.Fatal("login sem verificação do usuário foi aceito")
	}
}

func TestRegistrationCeremonyBoundToUser(t *testing.T) {
	e := newEnv(t)
	alice := e.newUser("alice@example.com")
	bob := e.newUser("bob@example.com")
	a := newSoftAuth(t, rpID, origin)
	opts, token, _ := e.svc.BeginRegistration(ctx, alice.ID)
	// Bob tenta concluir a cerimônia iniciada para a Alice.
	if err := e.svc.FinishRegistration(ctx, bob.ID, token, post(t, a.register(opts)), "x"); !errors.Is(err, ErrCeremony) {
		t.Fatalf("cerimônia de outro usuário aceita: %v", err)
	}
	if l, _ := e.svc.List(ctx, bob.ID); len(l) != 0 {
		t.Fatal("passkey foi parar na conta errada")
	}
}

func TestCeremonyKindsAreNotInterchangeable(t *testing.T) {
	e := newEnv(t)
	u := e.newUser("ana@example.com")
	a := e.enroll(t, u)
	// Um token de registro não serve para concluir login, e vice-versa.
	_, regToken, _ := e.svc.BeginRegistration(ctx, u.ID)
	opts, _, _ := e.svc.BeginLogin(ctx)
	if _, err := e.svc.FinishLogin(ctx, regToken, post(t, a.assert(opts, 1))); !errors.Is(err, ErrCeremony) {
		t.Fatalf("token de registro usado no login: %v", err)
	}
}

func TestUserHandleMustMatchCredentialOwner(t *testing.T) {
	e := newEnv(t)
	alice := e.newUser("alice@example.com")
	bob := e.newUser("bob@example.com")
	a := e.enroll(t, alice)
	opts, token, _ := e.svc.BeginLogin(ctx)
	a.userHandle = bob.ID[:] // autenticador afirma ser do Bob
	if _, err := e.svc.FinishLogin(ctx, token, post(t, a.assert(opts, 1))); err == nil {
		t.Fatal("user handle de outro usuário foi aceito")
	}
}

func TestSuspendedUserCannotLogin(t *testing.T) {
	e := newEnv(t)
	u := e.newUser("ana@example.com")
	a := e.enroll(t, u)
	u.Status = identity.StatusSuspended
	e.users.m[u.ID] = u
	opts, token, _ := e.svc.BeginLogin(ctx)
	if _, err := e.svc.FinishLogin(ctx, token, post(t, a.assert(opts, 1))); !errors.Is(err, ErrUserNotAllowed) {
		t.Fatalf("usuário suspenso autenticou: %v", err)
	}
	if _, _, err := e.svc.BeginRegistration(ctx, u.ID); !errors.Is(err, ErrUserNotAllowed) {
		t.Fatalf("usuário suspenso iniciou registro: %v", err)
	}
}

func TestRegistrationExcludesExistingCredentials(t *testing.T) {
	e := newEnv(t)
	u := e.newUser("ana@example.com")
	a := e.enroll(t, u)
	opts, _, _ := e.svc.BeginRegistration(ctx, u.ID)
	raw, _ := json.Marshal(opts)
	var top struct {
		PublicKey struct {
			Exclude []struct {
				ID string `json:"id"`
			} `json:"excludeCredentials"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(raw, &top); err != nil {
		t.Fatal(err)
	}
	if len(top.PublicKey.Exclude) != 1 || top.PublicKey.Exclude[0].ID != b64.EncodeToString(a.credID) {
		t.Fatalf("excludeCredentials = %+v", top.PublicKey.Exclude)
	}
}

func TestLimitPerUser(t *testing.T) {
	e := newEnv(t)
	u := e.newUser("ana@example.com")
	for range MaxPerUser {
		e.enroll(t, u)
	}
	if _, _, err := e.svc.BeginRegistration(ctx, u.ID); !errors.Is(err, ErrLimit) {
		t.Fatalf("passou do limite de passkeys: %v", err)
	}
}

func TestRemoveOnlyByOwner(t *testing.T) {
	e := newEnv(t)
	alice := e.newUser("alice@example.com")
	bob := e.newUser("bob@example.com")
	a := e.enroll(t, alice)
	if err := e.svc.Remove(ctx, bob.ID, a.credID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Bob removeu passkey da Alice: %v", err)
	}
	if err := e.svc.Remove(ctx, alice.ID, a.credID); err != nil {
		t.Fatal(err)
	}
	// Depois de removida, não loga mais.
	opts, token, _ := e.svc.BeginLogin(ctx)
	if _, err := e.svc.FinishLogin(ctx, token, post(t, a.assert(opts, 1))); err == nil {
		t.Fatal("passkey removida ainda autentica")
	}
}

func TestBadConfig(t *testing.T) {
	clk := clock.NewFake(t0)
	_, err := New(Config{RPID: rpID, RPDisplayName: "x", RPOrigins: []string{"http://inseguro.example.com"}},
		NewMemoryCredentials(), &fakeUsers{}, ephemeral.NewMemory(clk), clk, nil)
	_ = err // a biblioteca decide o que aceita; o importante é não entrar em pânico
	if _, err := New(Config{}, nil, nil, nil, nil, nil); err == nil {
		t.Fatal("dependências ausentes aceitas")
	}
}
