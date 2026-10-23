//go:build integration

package authflow_test

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Americo509/alo-api/internal/clock"
	"github.com/Americo509/alo-api/internal/identity"
	"github.com/Americo509/alo-api/internal/identity/authflow"
	"github.com/Americo509/alo-api/internal/identity/authtoken"
	"github.com/Americo509/alo-api/internal/identity/password"
	"github.com/Americo509/alo-api/internal/identity/pwpolicy"
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

// recordMailer registra o que seria enviado, para o teste inspecionar.
type recordMailer struct {
	mu            sync.Mutex
	verification  map[string]string // email -> token
	recovery      map[string]string
	accountExists []string
	changed       []string
}

func newMailer() *recordMailer {
	return &recordMailer{verification: map[string]string{}, recovery: map[string]string{}}
}

func (m *recordMailer) SendEmailVerification(_ context.Context, to, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.verification[to] = token
	return nil
}
func (m *recordMailer) SendPasswordRecovery(_ context.Context, to, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.recovery[to] = token
	return nil
}
func (m *recordMailer) SendPasswordChanged(_ context.Context, to string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.changed = append(m.changed, to)
	return nil
}
func (m *recordMailer) SendAccountExists(_ context.Context, to string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.accountExists = append(m.accountExists, to)
	return nil
}

func newService(t *testing.T, mailer authflow.Mailer) *authflow.Service {
	t.Helper()
	clk := clock.NewFake(time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC))
	h, err := password.NewHasher(nil, password.WithParams(password.Params{Memory: 8 * 1024, Time: 1, Parallelism: 1, SaltLen: 16, KeyLen: 32}))
	if err != nil {
		t.Fatal(err)
	}
	svc, err := authflow.New(authflow.Deps{
		Pool:   db.App,
		Users:  identity.NewRepo(db.App),
		Tokens: authtoken.New(db.App, clk),
		Hasher: h,
		Policy: pwpolicy.Policy{MinLength: 12}, // sem BreachChecker: offline
		Mailer: mailer,
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func email() string { return uuid.NewString() + "@example.com" }

func TestRegisterVerifyLogin(t *testing.T) {
	ctx := context.Background()
	mailer := newMailer()
	svc := newService(t, mailer)
	e, pw := email(), "senha-bem-grande-123"

	if err := svc.Register(ctx, e, pw); err != nil {
		t.Fatalf("Register: %v", err)
	}
	token := mailer.verification[e]
	if token == "" {
		t.Fatal("verificação não enviada")
	}

	// Antes de verificar, o login já funciona (verificação não bloqueia login
	// neste passo; o gate de verificação é decisão de borda), mas o usuário
	// está não-verificado.
	u, rehash, err := svc.Login(ctx, e, pw)
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if u.EmailVerified {
		t.Fatal("e-mail não deveria estar verificado ainda")
	}
	_ = rehash

	if err := svc.VerifyEmail(ctx, token); err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}
	u, _, _ = svc.Login(ctx, e, pw)
	if !u.EmailVerified {
		t.Fatal("e-mail deveria estar verificado após VerifyEmail")
	}
}

func TestLoginWrongPasswordAndUnknownUserSameError(t *testing.T) {
	ctx := context.Background()
	svc := newService(t, newMailer())
	e, pw := email(), "senha-bem-grande-123"
	_ = svc.Register(ctx, e, pw)

	_, _, err1 := svc.Login(ctx, e, "outra-senha-qualquer")
	_, _, err2 := svc.Login(ctx, email(), "qualquer-coisa-123")
	if !errors.Is(err1, authflow.ErrInvalidCredentials) || !errors.Is(err2, authflow.ErrInvalidCredentials) {
		t.Fatalf("erros diferentes: senha=%v, usuário=%v", err1, err2)
	}
}

func TestRegisterDuplicateDoesNotReveal(t *testing.T) {
	ctx := context.Background()
	mailer := newMailer()
	svc := newService(t, mailer)
	e := email()
	if err := svc.Register(ctx, e, "senha-bem-grande-123"); err != nil {
		t.Fatal(err)
	}
	// Segundo cadastro com o mesmo e-mail: resposta idêntica (nil), e NÃO cria
	// verificação nova; manda aviso de conta existente.
	if err := svc.Register(ctx, e, "outra-senha-diferente"); err != nil {
		t.Fatalf("cadastro duplicado revelou erro: %v", err)
	}
	if len(mailer.accountExists) != 1 || mailer.accountExists[0] != e {
		t.Fatalf("aviso de conta existente não enviado: %v", mailer.accountExists)
	}
	// A senha original continua válida (não foi sobrescrita).
	if _, _, err := svc.Login(ctx, e, "senha-bem-grande-123"); err != nil {
		t.Fatalf("senha original invalidada pelo cadastro duplicado: %v", err)
	}
	if _, _, err := svc.Login(ctx, e, "outra-senha-diferente"); !errors.Is(err, authflow.ErrInvalidCredentials) {
		t.Fatal("cadastro duplicado trocou a senha")
	}
}

func TestPasswordRecovery(t *testing.T) {
	ctx := context.Background()
	mailer := newMailer()
	svc := newService(t, mailer)
	e := email()
	_ = svc.Register(ctx, e, "senha-original-1234")

	if err := svc.StartPasswordRecovery(ctx, e); err != nil {
		t.Fatal(err)
	}
	token := mailer.recovery[e]
	if token == "" {
		t.Fatal("recuperação não enviada")
	}
	uid, err := svc.CompletePasswordRecovery(ctx, token, "senha-nova-567890")
	if err != nil || uid == uuid.Nil {
		t.Fatalf("CompletePasswordRecovery: %v %v", uid, err)
	}
	// Senha nova funciona, antiga não.
	if _, _, err := svc.Login(ctx, e, "senha-nova-567890"); err != nil {
		t.Fatalf("nova senha não funciona: %v", err)
	}
	if _, _, err := svc.Login(ctx, e, "senha-original-1234"); !errors.Is(err, authflow.ErrInvalidCredentials) {
		t.Fatal("senha antiga ainda funciona")
	}
	// Token de recuperação é de uso único.
	if _, err := svc.CompletePasswordRecovery(ctx, token, "mais-uma-senha-999"); !errors.Is(err, authtoken.ErrInvalid) {
		t.Fatalf("token de recuperação reusado: %v", err)
	}
	if len(mailer.changed) != 1 {
		t.Fatalf("aviso de troca de senha: %v", mailer.changed)
	}
}

func TestStartRecoveryUnknownEmailIsSilent(t *testing.T) {
	ctx := context.Background()
	mailer := newMailer()
	svc := newService(t, mailer)
	if err := svc.StartPasswordRecovery(ctx, email()); err != nil {
		t.Fatalf("recuperação de e-mail inexistente deveria ser silenciosa: %v", err)
	}
	if err := svc.StartPasswordRecovery(ctx, "e-mail-malformado"); err != nil {
		t.Fatalf("recuperação de e-mail inválido deveria ser silenciosa: %v", err)
	}
	if len(mailer.recovery) != 0 {
		t.Fatal("recuperação enviada para e-mail que não existe")
	}
}

func TestRegisterRejectsWeakPassword(t *testing.T) {
	ctx := context.Background()
	svc := newService(t, newMailer())
	if err := svc.Register(ctx, email(), "curta"); !errors.Is(err, pwpolicy.ErrTooShort) {
		t.Fatalf("senha curta aceita no cadastro: %v", err)
	}
}
