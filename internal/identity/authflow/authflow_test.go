package authflow_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Americo509/alo-api/internal/clock"
	"github.com/Americo509/alo-api/internal/identity"
	"github.com/Americo509/alo-api/internal/identity/authflow"
	"github.com/Americo509/alo-api/internal/identity/authtoken"
	"github.com/Americo509/alo-api/internal/identity/password"
	"github.com/Americo509/alo-api/internal/identity/pwpolicy"
)

var (
	uctx = context.Background()
	ut0  = time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
)

// --- dublês em memória -------------------------------------------------------

type memState struct {
	users map[uuid.UUID]identity.User
	pw    map[uuid.UUID]string
	toks  map[string]memTok
}

type memTok struct {
	user    uuid.UUID
	purpose authtoken.Purpose
	expires time.Time
	used    bool
}

// mem implementa authflow.Store, authflow.Tokens e authflow.Atomic juntos, com
// rollback por cópia do estado (simula a transação).
type mem struct {
	mu  sync.Mutex
	clk *clock.Fake
	st  memState
	seq int

	failSetPassword bool
}

func newMem(clk *clock.Fake) *mem {
	return &mem{clk: clk, st: memState{
		users: map[uuid.UUID]identity.User{}, pw: map[uuid.UUID]string{}, toks: map[string]memTok{},
	}}
}

func (m *mem) snapshot() memState {
	c := memState{users: map[uuid.UUID]identity.User{}, pw: map[uuid.UUID]string{}, toks: map[string]memTok{}}
	for k, v := range m.st.users {
		c.users[k] = v
	}
	for k, v := range m.st.pw {
		c.pw[k] = v
	}
	for k, v := range m.st.toks {
		c.toks[k] = v
	}
	return c
}

func (m *mem) Do(ctx context.Context, fn func(authflow.Store, authflow.Tokens) error) error {
	m.mu.Lock()
	snap := m.snapshot()
	m.mu.Unlock()
	if err := fn(m, m); err != nil {
		m.mu.Lock()
		m.st = snap
		m.mu.Unlock()
		return err
	}
	return nil
}

func (m *mem) GetUserByEmail(_ context.Context, email string) (identity.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, u := range m.st.users {
		if strings.EqualFold(u.Email, email) {
			return u, nil
		}
	}
	return identity.User{}, identity.ErrNotFound
}

func (m *mem) GetUser(_ context.Context, id uuid.UUID) (identity.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.st.users[id]
	if !ok {
		return identity.User{}, identity.ErrNotFound
	}
	return u, nil
}

func (m *mem) GetPassword(_ context.Context, id uuid.UUID) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.st.pw[id]
	if !ok {
		return "", identity.ErrNoPassword
	}
	return p, nil
}

func (m *mem) SetPassword(_ context.Context, id uuid.UUID, phc string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failSetPassword {
		return errors.New("falha simulada ao gravar a senha")
	}
	m.st.pw[id] = phc
	return nil
}

func (m *mem) CreateUser(_ context.Context, email, name string, verified bool) (identity.User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, u := range m.st.users {
		if strings.EqualFold(u.Email, email) {
			return identity.User{}, identity.ErrEmailTaken
		}
	}
	u := identity.User{ID: uuid.New(), Email: email, DisplayName: name, EmailVerified: verified, Status: identity.StatusActive}
	m.st.users[u.ID] = u
	return u, nil
}

func (m *mem) SetEmailVerified(_ context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u := m.st.users[id]
	u.EmailVerified = true
	m.st.users[id] = u
	return nil
}

func (m *mem) setStatus(id uuid.UUID, s identity.Status) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u := m.st.users[id]
	u.Status = s
	m.st.users[id] = u
}

func (m *mem) Issue(_ context.Context, userID uuid.UUID, p authtoken.Purpose) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seq++
	tok := fmt.Sprintf("tok-%d-%s", m.seq, uuid.NewString())
	ttl := 24 * time.Hour
	if p == authtoken.PurposePasswordRecovery {
		ttl = 30 * time.Minute
	}
	m.st.toks[tok] = memTok{user: userID, purpose: p, expires: m.clk.Now().Add(ttl)}
	return tok, nil
}

func (m *mem) Consume(_ context.Context, token string, p authtoken.Purpose) (uuid.UUID, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.st.toks[token]
	if !ok || t.used || t.purpose != p || !m.clk.Now().Before(t.expires) {
		return uuid.Nil, authtoken.ErrInvalid
	}
	t.used = true
	m.st.toks[token] = t
	return t.user, nil
}

func (m *mem) InvalidateAll(_ context.Context, userID uuid.UUID, p authtoken.Purpose) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, t := range m.st.toks {
		if t.user == userID && t.purpose == p {
			t.used = true
			m.st.toks[k] = t
		}
	}
	return nil
}

type unitMailer struct {
	mu            sync.Mutex
	verification  map[string]string
	recovery      map[string]string
	accountExists []string
	changed       []string
}

func newUnitMailer() *unitMailer {
	return &unitMailer{verification: map[string]string{}, recovery: map[string]string{}}
}

func (m *unitMailer) SendEmailVerification(_ context.Context, to, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.verification[to] = token
	return nil
}

func (m *unitMailer) SendPasswordRecovery(_ context.Context, to, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.recovery[to] = token
	return nil
}

func (m *unitMailer) SendPasswordChanged(_ context.Context, to string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.changed = append(m.changed, to)
	return nil
}

func (m *unitMailer) SendAccountExists(_ context.Context, to string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.accountExists = append(m.accountExists, to)
	return nil
}

// countingHasher conta as chamadas a Verify (para provar que os caminhos de
// "usuário inexistente" pagam o mesmo custo de hash).
type countingHasher struct {
	inner    authflow.Hasher
	verifies atomic.Int32
}

func (h *countingHasher) Hash(p []byte) (string, error) { return h.inner.Hash(p) }
func (h *countingHasher) Verify(p []byte, e string) (bool, bool, error) {
	h.verifies.Add(1)
	return h.inner.Verify(p, e)
}

func fastParams(memKiB uint32) password.Params {
	return password.Params{Memory: memKiB, Time: 1, Parallelism: 1, SaltLen: 16, KeyLen: 32}
}

func realHasher(t *testing.T, memKiB uint32) *password.Hasher {
	t.Helper()
	h, err := password.NewHasher(nil, password.WithParams(fastParams(memKiB)))
	if err != nil {
		t.Fatal(err)
	}
	return h
}

type unitEnv struct {
	svc    *authflow.Service
	mem    *mem
	mailer *unitMailer
	hasher *countingHasher
	clk    *clock.Fake
}

func newUnitEnv(t *testing.T) *unitEnv {
	t.Helper()
	clk := clock.NewFake(ut0)
	m := newMem(clk)
	ml := newUnitMailer()
	h := &countingHasher{inner: realHasher(t, 8*1024)}
	svc, err := authflow.New(authflow.Deps{
		Store: m, Tokens: m, Atomic: m, Hasher: h, Policy: pwpolicy.Policy{MinLength: 12}, Mailer: ml,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &unitEnv{svc: svc, mem: m, mailer: ml, hasher: h, clk: clk}
}

func uniq() string { return uuid.NewString() + "@example.com" }

const goodPW = "senha-bem-grande-123"

// --- cadastro ---------------------------------------------------------------------

func TestUnitRegisterVerifyLogin(t *testing.T) {
	e := newUnitEnv(t)
	em := uniq()
	if err := e.svc.Register(uctx, strings.ToUpper(em), goodPW); err != nil {
		t.Fatal(err)
	}
	token := e.mailer.verification[em] // e-mail normalizado em minúsculas
	if token == "" {
		t.Fatalf("verificação não enviada: %v", e.mailer.verification)
	}
	u, _, err := e.svc.Login(uctx, em, goodPW)
	if err != nil || u.EmailVerified {
		t.Fatalf("login antes de verificar: %+v %v", u, err)
	}
	if err := e.svc.VerifyEmail(uctx, token); err != nil {
		t.Fatal(err)
	}
	if u, _, _ = e.svc.Login(uctx, em, goodPW); !u.EmailVerified {
		t.Fatal("e-mail deveria estar verificado")
	}
	// Uso único.
	if err := e.svc.VerifyEmail(uctx, token); !errors.Is(err, authtoken.ErrInvalid) {
		t.Fatalf("token reutilizado: %v", err)
	}
}

func TestUnitRegisterDuplicateLooksIdentical(t *testing.T) {
	e := newUnitEnv(t)
	em := uniq()
	if err := e.svc.Register(uctx, em, goodPW); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.Register(uctx, em, "outra-senha-diferente"); err != nil {
		t.Fatalf("cadastro duplicado revelou erro: %v", err)
	}
	if len(e.mailer.accountExists) != 1 || e.mailer.accountExists[0] != em {
		t.Fatalf("aviso de conta existente: %v", e.mailer.accountExists)
	}
	if _, _, err := e.svc.Login(uctx, em, goodPW); err != nil {
		t.Fatalf("senha original invalidada: %v", err)
	}
	if _, _, err := e.svc.Login(uctx, em, "outra-senha-diferente"); !errors.Is(err, authflow.ErrInvalidCredentials) {
		t.Fatal("o cadastro duplicado trocou a senha")
	}
}

func TestUnitRegisterValidation(t *testing.T) {
	e := newUnitEnv(t)
	if err := e.svc.Register(uctx, uniq(), "curta"); !errors.Is(err, pwpolicy.ErrTooShort) {
		t.Fatalf("senha curta: %v", err)
	}
	if err := e.svc.Register(uctx, "isto-nao-e-email", goodPW); err == nil {
		t.Fatal("e-mail inválido aceito")
	}
	if len(e.mem.st.users) != 0 {
		t.Fatal("usuário criado apesar da validação")
	}
}

// Se gravar a senha falha, o usuário também não fica (atomicidade).
func TestUnitRegisterIsAtomic(t *testing.T) {
	e := newUnitEnv(t)
	e.mem.failSetPassword = true
	if err := e.svc.Register(uctx, uniq(), goodPW); err == nil {
		t.Fatal("esperava erro")
	}
	if len(e.mem.st.users) != 0 {
		t.Fatalf("usuário ficou órfão: %d", len(e.mem.st.users))
	}
	if len(e.mailer.verification) != 0 {
		t.Fatal("e-mail de verificação enviado para cadastro que falhou")
	}
}

// --- login ----------------------------------------------------------------------------

func TestUnitLoginErrorsAreIndistinguishable(t *testing.T) {
	e := newUnitEnv(t)
	em := uniq()
	_ = e.svc.Register(uctx, em, goodPW)

	// Conta social, sem senha.
	social, _ := e.mem.CreateUser(uctx, uniq(), "", true)

	suspended := uniq()
	_ = e.svc.Register(uctx, suspended, goodPW)
	su, _ := e.mem.GetUserByEmail(uctx, suspended)
	e.mem.setStatus(su.ID, identity.StatusSuspended)

	cases := map[string]struct{ email, pw string }{
		"senha errada":     {em, "senha-errada-qualquer"},
		"usuário inexiste": {uniq(), goodPW},
		"sem senha":        {social.Email, goodPW},
		"conta suspensa":   {suspended, goodPW},
		"e-mail inválido":  {"lixo", goodPW},
	}
	for name, c := range cases {
		_, _, err := e.svc.Login(uctx, c.email, c.pw)
		if !errors.Is(err, authflow.ErrInvalidCredentials) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Todo caminho de falha paga o custo de exatamente um Verify (sem oráculo de tempo).
func TestUnitLoginFailuresCostOneVerify(t *testing.T) {
	e := newUnitEnv(t)
	em := uniq()
	_ = e.svc.Register(uctx, em, goodPW)
	social, _ := e.mem.CreateUser(uctx, uniq(), "", true)

	for name, c := range map[string]struct{ email, pw string }{
		"senha errada":    {em, "senha-errada-qualquer"},
		"inexistente":     {uniq(), goodPW},
		"sem senha":       {social.Email, goodPW},
		"e-mail inválido": {"lixo", goodPW},
	} {
		before := e.hasher.verifies.Load()
		_, _, _ = e.svc.Login(uctx, c.email, c.pw)
		if got := e.hasher.verifies.Load() - before; got != 1 {
			t.Errorf("%s: %d chamadas a Verify, quer 1", name, got)
		}
	}
}

func TestUnitLoginSuggestsRehashAndRehashWorks(t *testing.T) {
	clk := clock.NewFake(ut0)
	m := newMem(clk)
	weak := realHasher(t, 8*1024)
	strong := realHasher(t, 16*1024)

	// Usuário criado quando os parâmetros eram mais fracos.
	u, _ := m.CreateUser(uctx, uniq(), "", true)
	old, _ := weak.Hash([]byte(goodPW))
	_ = m.SetPassword(uctx, u.ID, old)

	svc, _ := authflow.New(authflow.Deps{Store: m, Tokens: m, Atomic: m, Hasher: strong, Policy: pwpolicy.Policy{MinLength: 12}, Mailer: newUnitMailer()})
	_, needs, err := svc.Login(uctx, u.Email, goodPW)
	if err != nil || !needs {
		t.Fatalf("Login: needsRehash=%t err=%v", needs, err)
	}
	if err := svc.Rehash(uctx, u.ID, goodPW); err != nil {
		t.Fatal(err)
	}
	if _, needs, err = svc.Login(uctx, u.Email, goodPW); err != nil || needs {
		t.Fatalf("depois do Rehash: needsRehash=%t err=%v", needs, err)
	}
}

func TestUnitVerifyPassword(t *testing.T) {
	e := newUnitEnv(t)
	em := uniq()
	_ = e.svc.Register(uctx, em, goodPW)
	u, _ := e.mem.GetUserByEmail(uctx, em)
	if err := e.svc.VerifyPassword(uctx, u.ID, goodPW); err != nil {
		t.Fatal(err)
	}
	if err := e.svc.VerifyPassword(uctx, u.ID, "errada-errada-123"); !errors.Is(err, authflow.ErrInvalidCredentials) {
		t.Fatalf("senha errada: %v", err)
	}
	social, _ := e.mem.CreateUser(uctx, uniq(), "", true)
	if err := e.svc.VerifyPassword(uctx, social.ID, goodPW); !errors.Is(err, authflow.ErrInvalidCredentials) {
		t.Fatalf("conta sem senha: %v", err)
	}
}

// --- troca e recuperação de senha ----------------------------------------------------------

func TestUnitChangePassword(t *testing.T) {
	e := newUnitEnv(t)
	em := uniq()
	_ = e.svc.Register(uctx, em, goodPW)
	u, _ := e.mem.GetUserByEmail(uctx, em)
	// Um pedido de recuperação pendente deve morrer com a troca.
	_ = e.svc.StartPasswordRecovery(uctx, em)
	pending := e.mailer.recovery[em]

	if err := e.svc.ChangePassword(uctx, u.ID, "senha-atual-errada", "nova-senha-bem-grande"); !errors.Is(err, authflow.ErrInvalidCredentials) {
		t.Fatalf("senha atual errada: %v", err)
	}
	if err := e.svc.ChangePassword(uctx, u.ID, goodPW, "curta"); !errors.Is(err, pwpolicy.ErrTooShort) {
		t.Fatalf("senha nova fraca: %v", err)
	}
	if _, _, err := e.svc.Login(uctx, em, goodPW); err != nil {
		t.Fatal("as tentativas inválidas alteraram a senha")
	}
	if err := e.svc.ChangePassword(uctx, u.ID, goodPW, "nova-senha-bem-grande"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.Login(uctx, em, "nova-senha-bem-grande"); err != nil {
		t.Fatalf("nova senha não funciona: %v", err)
	}
	if _, _, err := e.svc.Login(uctx, em, goodPW); !errors.Is(err, authflow.ErrInvalidCredentials) {
		t.Fatal("a senha antiga ainda funciona")
	}
	if _, err := e.svc.CompletePasswordRecovery(uctx, pending, "outra-senha-bem-grande"); !errors.Is(err, authtoken.ErrInvalid) {
		t.Fatalf("recuperação pendente sobreviveu à troca de senha: %v", err)
	}
	if len(e.mailer.changed) != 1 || e.mailer.changed[0] != em {
		t.Fatalf("aviso de troca: %v", e.mailer.changed)
	}
}

func TestUnitPasswordRecovery(t *testing.T) {
	e := newUnitEnv(t)
	em := uniq()
	_ = e.svc.Register(uctx, em, "senha-original-1234")
	if err := e.svc.StartPasswordRecovery(uctx, em); err != nil {
		t.Fatal(err)
	}
	token := e.mailer.recovery[em]
	if token == "" {
		t.Fatal("recuperação não enviada")
	}
	// Senha fraca NÃO consome o token: o usuário pode tentar de novo.
	if _, err := e.svc.CompletePasswordRecovery(uctx, token, "curta"); !errors.Is(err, pwpolicy.ErrTooShort) {
		t.Fatalf("senha fraca: %v", err)
	}
	uid, err := e.svc.CompletePasswordRecovery(uctx, token, "senha-nova-567890")
	if err != nil || uid == uuid.Nil {
		t.Fatalf("CompletePasswordRecovery: %v %v", uid, err)
	}
	if _, _, err := e.svc.Login(uctx, em, "senha-nova-567890"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.svc.Login(uctx, em, "senha-original-1234"); !errors.Is(err, authflow.ErrInvalidCredentials) {
		t.Fatal("senha antiga ainda vale")
	}
	if _, err := e.svc.CompletePasswordRecovery(uctx, token, "mais-uma-senha-999"); !errors.Is(err, authtoken.ErrInvalid) {
		t.Fatalf("token de recuperação reutilizado: %v", err)
	}
	if len(e.mailer.changed) != 1 {
		t.Fatalf("aviso de troca: %v", e.mailer.changed)
	}
}

func TestUnitRecoveryTokenExpires(t *testing.T) {
	e := newUnitEnv(t)
	em := uniq()
	_ = e.svc.Register(uctx, em, goodPW)
	_ = e.svc.StartPasswordRecovery(uctx, em)
	e.clk.Advance(31 * time.Minute)
	if _, err := e.svc.CompletePasswordRecovery(uctx, e.mailer.recovery[em], "senha-nova-567890"); !errors.Is(err, authtoken.ErrInvalid) {
		t.Fatalf("token expirado aceito: %v", err)
	}
}

func TestUnitStartRecoveryIsSilentForUnknownAndInvalid(t *testing.T) {
	e := newUnitEnv(t)
	for _, em := range []string{uniq(), "e-mail-malformado", ""} {
		if err := e.svc.StartPasswordRecovery(uctx, em); err != nil {
			t.Errorf("%q: %v", em, err)
		}
	}
	if len(e.mailer.recovery) != 0 {
		t.Fatal("recuperação enviada para e-mail que não existe")
	}
}

func TestUnitNewValidation(t *testing.T) {
	if _, err := authflow.New(authflow.Deps{}); err == nil {
		t.Fatal("dependências ausentes aceitas")
	}
}
