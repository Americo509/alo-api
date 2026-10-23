package oidclogin

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Americo509/alo-api/internal/clock"
	"github.com/Americo509/alo-api/internal/identity"
	"github.com/Americo509/alo-api/internal/identity/ephemeral"
)

var (
	ctx = context.Background()
	t0  = time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
)

const (
	clientID = "client-123"
	redirect = "http://localhost:8080/auth/google/callback"
)

type env struct {
	svc *Service
	idp *fakeIdP
	acc *MemoryAccounts
	clk *clock.Fake
}

func newEnv(t *testing.T, formPost bool) *env {
	t.Helper()
	clk := clock.NewFake(t0)
	idp := newFakeIdP(t, t0)
	p, err := NewProvider(ctx, ProviderConfig{
		Name: "google", Issuer: idp.URL(), ClientID: clientID, RedirectURL: redirect,
		Secret: StaticSecret("s3cret"), FormPost: formPost, HTTPClient: idp.srv.Client(), AllowInsecureHTTP: true,
	}, clk.Now)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	acc := NewMemoryAccounts()
	svc, err := New([]*Provider{p}, acc, ephemeral.NewMemory(clk), clk, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &env{svc: svc, idp: idp, acc: acc, clk: clk}
}

func claims(sub, email string, verified any) map[string]any {
	return map[string]any{"sub": sub, "email": email, "email_verified": verified, "name": "Ana Teste"}
}

// run faz Begin → provedor aprova → Callback.
func (e *env) run(t *testing.T, c map[string]any, opts tokenOpts) (Result, error) {
	t.Helper()
	br, err := e.svc.Begin(ctx, "google", IntentLogin, uuid.Nil)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	code, state := e.idp.issueCode(br.AuthURL, c, opts)
	return e.svc.Callback(ctx, CallbackInput{Provider: "google", State: state, Code: code, Binding: br.Binding})
}

func TestAuthURLIsHardened(t *testing.T) {
	e := newEnv(t, false)
	br, err := e.svc.Begin(ctx, "google", IntentLogin, uuid.Nil)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(br.AuthURL)
	q := u.Query()
	for _, k := range []string{"state", "nonce", "code_challenge"} {
		if len(q.Get(k)) < 40 {
			t.Errorf("%s fraco ou ausente: %q", k, q.Get(k))
		}
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Error("PKCE não é S256")
	}
	if q.Get("redirect_uri") != redirect {
		t.Errorf("redirect_uri = %q, quer o fixo da configuração", q.Get("redirect_uri"))
	}
	if !strings.Contains(q.Get("scope"), "openid") {
		t.Errorf("scope sem openid: %q", q.Get("scope"))
	}
	if q.Get("response_mode") != "" {
		t.Errorf("response_mode = %q; só a Apple usa form_post", q.Get("response_mode"))
	}
	if br.Binding == "" || br.CrossSite {
		t.Errorf("binding=%q crossSite=%t", br.Binding, br.CrossSite)
	}
	// Dois inícios nunca repetem state/nonce/binding.
	br2, _ := e.svc.Begin(ctx, "google", IntentLogin, uuid.Nil)
	u2, _ := url.Parse(br2.AuthURL)
	if u2.Query().Get("state") == q.Get("state") || u2.Query().Get("nonce") == q.Get("nonce") || br2.Binding == br.Binding {
		t.Fatal("state/nonce/binding repetidos")
	}
}

func TestNewUserIsCreated(t *testing.T) {
	e := newEnv(t, false)
	res, err := e.run(t, claims("sub-1", "Ana@Example.com", true), tokenOpts{})
	if err != nil {
		t.Fatalf("Callback: %v", err)
	}
	if !res.Created || res.User.Email != "ana@example.com" || !res.User.EmailVerified || res.User.DisplayName != "Ana Teste" {
		t.Fatalf("resultado inesperado: %+v", res)
	}
	if e.acc.Identities() != 1 {
		t.Fatalf("vínculos = %d, quer 1", e.acc.Identities())
	}
	// O client_secret chegou ao provedor pelo corpo da troca.
	if e.idp.secretSeen != "s3cret" {
		t.Errorf("client_secret na troca = %q", e.idp.secretSeen)
	}
}

func TestReturningUserKeepsSameAccount(t *testing.T) {
	e := newEnv(t, false)
	first, _ := e.run(t, claims("sub-1", "ana@example.com", true), tokenOpts{})
	// Mesmo subject; o e-mail mudou no provedor. A conta é a mesma.
	again, err := e.run(t, claims("sub-1", "ana.nova@example.com", true), tokenOpts{})
	if err != nil {
		t.Fatal(err)
	}
	if again.Created || again.User.ID != first.User.ID {
		t.Fatalf("login recorrente criou/trocou conta: %+v", again)
	}
}

// O ponto mais importante: ter o mesmo e-mail no provedor NÃO dá acesso a uma
// conta existente com esse e-mail (evita tomada de conta).
func TestNeverAutoLinksByEmail(t *testing.T) {
	e := newEnv(t, false)
	victim := identity.User{ID: uuid.New(), Email: "ana@example.com", EmailVerified: true, Status: identity.StatusActive}
	e.acc.AddUser(victim)

	_, err := e.run(t, claims("attacker-sub", "Ana@Example.com", true), tokenOpts{})
	if !errors.Is(err, ErrAccountExists) {
		t.Fatalf("login por e-mail igual deveria ser recusado: %v", err)
	}
	if e.acc.Identities() != 0 {
		t.Fatal("um vínculo foi criado automaticamente pelo e-mail")
	}
}

func TestUnverifiedEmailCreatesNothing(t *testing.T) {
	e := newEnv(t, false)
	for name, c := range map[string]map[string]any{
		"não verificado":  claims("s1", "x@example.com", false),
		"sem e-mail":      {"sub": "s2"},
		"e-mail inválido": claims("s3", "isto-nao-e-email", true),
	} {
		if _, err := e.run(t, c, tokenOpts{}); !errors.Is(err, ErrEmailUnverified) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if e.acc.Identities() != 0 {
		t.Fatal("criou vínculo sem e-mail verificado")
	}
}

func TestStateIsSingleUse(t *testing.T) {
	e := newEnv(t, false)
	br, _ := e.svc.Begin(ctx, "google", IntentLogin, uuid.Nil)
	code, state := e.idp.issueCode(br.AuthURL, claims("s1", "a@example.com", true), tokenOpts{})
	in := CallbackInput{Provider: "google", State: state, Code: code, Binding: br.Binding}
	if _, err := e.svc.Callback(ctx, in); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Callback(ctx, in); !errors.Is(err, ErrState) {
		t.Fatalf("replay do callback aceito: %v", err)
	}
}

func TestStateExpires(t *testing.T) {
	e := newEnv(t, false)
	br, _ := e.svc.Begin(ctx, "google", IntentLogin, uuid.Nil)
	code, state := e.idp.issueCode(br.AuthURL, claims("s1", "a@example.com", true), tokenOpts{})
	e.clk.Advance(11 * time.Minute)
	_, err := e.svc.Callback(ctx, CallbackInput{Provider: "google", State: state, Code: code, Binding: br.Binding})
	if !errors.Is(err, ErrState) {
		t.Fatalf("state expirado aceito: %v", err)
	}
}

// Login CSRF: o atacante inicia o fluxo e faz a vítima concluir o callback dele.
// Sem o cookie de binding do navegador que iniciou, o callback é recusado.
func TestBindingStopsLoginCSRF(t *testing.T) {
	e := newEnv(t, false)
	attacker, _ := e.svc.Begin(ctx, "google", IntentLogin, uuid.Nil)
	code, state := e.idp.issueCode(attacker.AuthURL, claims("s1", "a@example.com", true), tokenOpts{})

	for name, binding := range map[string]string{"vazio": "", "de outro fluxo": "outro-valor"} {
		br, _ := e.svc.Begin(ctx, "google", IntentLogin, uuid.Nil) // novo state a cada tentativa
		c, st := e.idp.issueCode(br.AuthURL, claims("s1", "a@example.com", true), tokenOpts{})
		_, err := e.svc.Callback(ctx, CallbackInput{Provider: "google", State: st, Code: c, Binding: binding})
		if !errors.Is(err, ErrState) {
			t.Errorf("binding %s aceito: %v", name, err)
		}
	}
	// O state do atacante, mesmo com o binding certo depois de uma tentativa
	// errada, já foi consumido.
	_, _ = e.svc.Callback(ctx, CallbackInput{Provider: "google", State: state, Code: code, Binding: "errado"})
	if _, err := e.svc.Callback(ctx, CallbackInput{Provider: "google", State: state, Code: code, Binding: attacker.Binding}); !errors.Is(err, ErrState) {
		t.Fatalf("state reaproveitado após tentativa inválida: %v", err)
	}
}

func TestStateFromAnotherProviderRejected(t *testing.T) {
	e := newEnv(t, false)
	// Segundo provedor "apple" apontando para o mesmo IdP de teste.
	other, err := NewProvider(ctx, ProviderConfig{
		Name: "apple", Issuer: e.idp.URL(), ClientID: clientID, RedirectURL: redirect,
		Secret: StaticSecret("x"), HTTPClient: e.idp.srv.Client(), AllowInsecureHTTP: true,
	}, e.clk.Now)
	if err != nil {
		t.Fatal(err)
	}
	svc, _ := New([]*Provider{e.svc.providers["google"], other}, e.acc, ephemeral.NewMemory(e.clk), e.clk, nil)
	br, _ := svc.Begin(ctx, "google", IntentLogin, uuid.Nil)
	code, state := e.idp.issueCode(br.AuthURL, claims("s1", "a@example.com", true), tokenOpts{})
	if _, err := svc.Callback(ctx, CallbackInput{Provider: "apple", State: state, Code: code, Binding: br.Binding}); !errors.Is(err, ErrState) {
		t.Fatalf("state de um provedor usado em outro: %v", err)
	}
}

func TestInvalidIDTokensAreRejected(t *testing.T) {
	e := newEnv(t, false)
	wrongKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	badNonce := "nonce-de-outro-fluxo"
	cases := map[string]tokenOpts{
		"assinatura de outra chave": {signWith: wrongKey},
		"nonce diferente":           {nonce: &badNonce},
		"audiência errada":          {aud: "outro-client-id"},
		"emissor errado":            {iss: "https://evil.example.com"},
		"expirado":                  {exp: t0.Add(-time.Hour)},
	}
	for name, opts := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := e.run(t, claims("s-"+name, "x"+name[:3]+"@example.com", true), opts); !errors.Is(err, ErrToken) {
				t.Fatalf("id_token inválido aceito: %v", err)
			}
		})
	}
	if e.acc.Identities() != 0 {
		t.Fatal("alguma conta foi criada a partir de id_token inválido")
	}
}

func TestWrongCodeVerifierFailsAtProvider(t *testing.T) {
	// O provedor falso valida o PKCE: um código obtido num fluxo não troca no outro.
	e := newEnv(t, false)
	a, _ := e.svc.Begin(ctx, "google", IntentLogin, uuid.Nil)
	b, _ := e.svc.Begin(ctx, "google", IntentLogin, uuid.Nil)
	codeA, _ := e.idp.issueCode(a.AuthURL, claims("s1", "a@example.com", true), tokenOpts{})
	_, stateB := e.idp.issueCode(b.AuthURL, claims("s1", "a@example.com", true), tokenOpts{})
	// Código do fluxo A com state/binding do fluxo B → o verifier de B não confere com o challenge de A.
	_, err := e.svc.Callback(ctx, CallbackInput{Provider: "google", State: stateB, Code: codeA, Binding: b.Binding})
	if !errors.Is(err, ErrToken) {
		t.Fatalf("código injetado de outro fluxo aceito: %v", err)
	}
}

func TestSuspendedUserCannotLogIn(t *testing.T) {
	e := newEnv(t, false)
	first, _ := e.run(t, claims("sub-1", "ana@example.com", true), tokenOpts{})
	e.acc.SetStatus(first.User.ID, identity.StatusSuspended)
	if _, err := e.run(t, claims("sub-1", "ana@example.com", true), tokenOpts{}); !errors.Is(err, ErrUserNotAllowed) {
		t.Fatalf("usuário suspenso entrou: %v", err)
	}
}

func TestMissingCodeAndUnknownProvider(t *testing.T) {
	e := newEnv(t, false)
	br, _ := e.svc.Begin(ctx, "google", IntentLogin, uuid.Nil)
	_, state := e.idp.issueCode(br.AuthURL, claims("s", "a@example.com", true), tokenOpts{})
	if _, err := e.svc.Callback(ctx, CallbackInput{Provider: "google", State: state, Binding: br.Binding}); !errors.Is(err, ErrToken) {
		t.Fatalf("callback sem código: %v", err)
	}
	if _, err := e.svc.Begin(ctx, "facebook", IntentLogin, uuid.Nil); !errors.Is(err, ErrUnknownProvider) {
		t.Fatalf("Begin com provedor desconhecido: %v", err)
	}
	if _, err := e.svc.Callback(ctx, CallbackInput{Provider: "facebook"}); !errors.Is(err, ErrUnknownProvider) {
		t.Fatalf("Callback com provedor desconhecido: %v", err)
	}
	for _, bad := range []string{"", "!!!", "curto"} {
		if _, err := e.svc.Callback(ctx, CallbackInput{Provider: "google", State: bad, Code: "x", Binding: "y"}); !errors.Is(err, ErrState) {
			t.Errorf("state malformado %q: %v", bad, err)
		}
	}
}

// --- vínculo a conta existente ------------------------------------------------

func (e *env) link(t *testing.T, owner uuid.UUID, sessionUser uuid.UUID, sub string) (Result, error) {
	t.Helper()
	br, err := e.svc.Begin(ctx, "google", IntentLink, owner)
	if err != nil {
		t.Fatalf("Begin(link): %v", err)
	}
	code, state := e.idp.issueCode(br.AuthURL, claims(sub, "qualquer@example.com", true), tokenOpts{})
	return e.svc.Callback(ctx, CallbackInput{Provider: "google", State: state, Code: code, Binding: br.Binding, SessionUserID: sessionUser})
}

func TestLinkToLoggedInUser(t *testing.T) {
	e := newEnv(t, false)
	u := identity.User{ID: uuid.New(), Email: "ana@example.com", Status: identity.StatusActive}
	e.acc.AddUser(u)

	res, err := e.link(t, u.ID, u.ID, "sub-ana")
	if err != nil || !res.Linked || res.User.ID != u.ID {
		t.Fatalf("link: %+v %v", res, err)
	}
	// A partir daí o login pelo provedor entra nessa conta.
	login, err := e.run(t, claims("sub-ana", "outro@example.com", true), tokenOpts{})
	if err != nil || login.User.ID != u.ID || login.Created {
		t.Fatalf("login após vínculo: %+v %v", login, err)
	}
}

func TestLinkRequiresSameLoggedInUser(t *testing.T) {
	e := newEnv(t, false)
	ana := identity.User{ID: uuid.New(), Email: "ana@example.com", Status: identity.StatusActive}
	bob := identity.User{ID: uuid.New(), Email: "bob@example.com", Status: identity.StatusActive}
	e.acc.AddUser(ana)
	e.acc.AddUser(bob)

	// A sessão atual é do Bob, mas o vínculo foi iniciado para a Ana.
	if _, err := e.link(t, ana.ID, bob.ID, "sub-x"); !errors.Is(err, ErrLinkMismatch) {
		t.Fatalf("vínculo com outro usuário logado: %v", err)
	}
	// Sem sessão.
	if _, err := e.link(t, ana.ID, uuid.Nil, "sub-y"); !errors.Is(err, ErrLinkMismatch) {
		t.Fatalf("vínculo sem sessão: %v", err)
	}
	if e.acc.Identities() != 0 {
		t.Fatal("algum vínculo foi criado indevidamente")
	}
}

func TestLinkIdentityAlreadyOwnedByAnother(t *testing.T) {
	e := newEnv(t, false)
	ana := identity.User{ID: uuid.New(), Email: "ana@example.com", Status: identity.StatusActive}
	bob := identity.User{ID: uuid.New(), Email: "bob@example.com", Status: identity.StatusActive}
	e.acc.AddUser(ana)
	e.acc.AddUser(bob)
	if _, err := e.link(t, ana.ID, ana.ID, "sub-compartilhado"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.link(t, bob.ID, bob.ID, "sub-compartilhado"); !errors.Is(err, ErrIdentityTaken) {
		t.Fatalf("mesma conta do provedor vinculada a dois usuários: %v", err)
	}
	// Repetir o vínculo ao próprio dono é inofensivo.
	if res, err := e.link(t, ana.ID, ana.ID, "sub-compartilhado"); err != nil || res.User.ID != ana.ID {
		t.Fatalf("vínculo repetido ao dono: %+v %v", res, err)
	}
}

func TestBeginLinkNeedsUser(t *testing.T) {
	e := newEnv(t, false)
	if _, err := e.svc.Begin(ctx, "google", IntentLink, uuid.Nil); err == nil {
		t.Fatal("IntentLink sem usuário aceito")
	}
	if _, err := e.svc.Begin(ctx, "google", Intent("hack"), uuid.Nil); err == nil {
		t.Fatal("intenção desconhecida aceita")
	}
}

// --- Apple (form_post, e-mail como string, nome só no primeiro login) ----------

func TestAppleStyleFlow(t *testing.T) {
	e := newEnv(t, true)
	br, err := e.svc.Begin(ctx, "google", IntentLogin, uuid.Nil)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(br.AuthURL)
	if u.Query().Get("response_mode") != "form_post" || !br.CrossSite {
		t.Fatalf("Apple precisa de form_post e cookie cross-site: %q %t", u.Query().Get("response_mode"), br.CrossSite)
	}
	// A Apple manda email_verified como string e o nome fora do id_token.
	c := map[string]any{"sub": "apple-sub", "email": "abc123@privaterelay.appleid.com", "email_verified": "true"}
	code, state := e.idp.issueCode(br.AuthURL, c, tokenOpts{})
	res, err := e.svc.Callback(ctx, CallbackInput{
		Provider: "google", State: state, Code: code, Binding: br.Binding,
		AppleUser: `{"name":{"firstName":"Bia","lastName":"Souza"},"email":"ignorado@x.com"}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Created || res.User.DisplayName != "Bia Souza" || res.User.Email != "abc123@privaterelay.appleid.com" {
		t.Fatalf("resultado Apple: %+v", res)
	}
}

// --- utilitários -----------------------------------------------------------------

func TestTruthy(t *testing.T) {
	for in, want := range map[any]bool{true: true, false: false, "true": true, "TRUE": true, "false": false, nil: false, 1: false, "": false} {
		if got := truthy(in); got != want {
			t.Errorf("truthy(%v) = %t", in, got)
		}
	}
}

func TestSanitizeName(t *testing.T) {
	if got := sanitizeName("  Ana\x00\n\tTeste\x07  "); got != "AnaTeste" {
		t.Errorf("sanitizeName = %q", got)
	}
	long := strings.Repeat("é", 500)
	if got := sanitizeName(long); len([]rune(got)) != 200 {
		t.Errorf("tamanho = %d, quer 200 caracteres", len([]rune(got)))
	}
	if appleDisplayName("não é json") != "" || appleDisplayName("") != "" {
		t.Error("appleDisplayName aceitou entrada inválida")
	}
}

func TestNewProviderValidation(t *testing.T) {
	clk := clock.NewFake(t0)
	base := ProviderConfig{Name: "g", Issuer: "https://accounts.example.com", ClientID: "c", RedirectURL: "https://app.example.com/cb", Secret: StaticSecret("s")}
	bad := map[string]func(*ProviderConfig){
		"sem nome":         func(c *ProviderConfig) { c.Name = "" },
		"sem segredo":      func(c *ProviderConfig) { c.Secret = nil },
		"issuer em http":   func(c *ProviderConfig) { c.Issuer = "http://accounts.example.com" },
		"redirect em http": func(c *ProviderConfig) { c.RedirectURL = "http://app.example.com/cb" },
		"issuer sem host":  func(c *ProviderConfig) { c.Issuer = "https://" },
	}
	for name, mutate := range bad {
		cfg := base
		mutate(&cfg)
		if _, err := NewProvider(ctx, cfg, clk.Now); err == nil {
			t.Errorf("%s: configuração inválida aceita", name)
		}
	}
}

func TestNewServiceValidation(t *testing.T) {
	clk := clock.NewFake(t0)
	if _, err := New(nil, nil, nil, nil, nil); err == nil {
		t.Error("dependências ausentes aceitas")
	}
	e := newEnv(t, false)
	p := e.svc.providers["google"]
	if _, err := New([]*Provider{p, p}, e.acc, ephemeral.NewMemory(clk), clk, nil); err == nil {
		t.Error("provedor duplicado aceito")
	}
}
