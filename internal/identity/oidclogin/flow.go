package oidclogin

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"golang.org/x/oauth2"

	"github.com/Americo509/alo-api/internal/clock"
	"github.com/Americo509/alo-api/internal/identity"
	"github.com/Americo509/alo-api/internal/identity/ephemeral"
)

// Intent é o objetivo do fluxo.
type Intent string

const (
	// IntentLogin: entrar (ou criar conta nova se não existir).
	IntentLogin Intent = "login"
	// IntentLink: vincular o provedor à conta do usuário JÁ autenticado.
	IntentLink Intent = "link"
)

// Erros. Mensagens para o cliente devem ser genéricas; o detalhe vai para log.
var (
	// ErrState: state inexistente, expirado, reutilizado, de outro navegador ou
	// de outro provedor.
	ErrState = errors.New("oidclogin: state inválido ou expirado")
	// ErrToken: falha na troca do código ou na validação do id_token.
	ErrToken = errors.New("oidclogin: não foi possível validar a resposta do provedor")
	// ErrAccountExists: já existe conta com este e-mail. Não vinculamos
	// automaticamente; o usuário entra com a senha e vincula nas configurações.
	ErrAccountExists = errors.New("oidclogin: já existe uma conta com este e-mail")
	// ErrEmailUnverified: o provedor não garante o e-mail; não criamos conta.
	ErrEmailUnverified = errors.New("oidclogin: e-mail ausente ou não verificado pelo provedor")
	// ErrUserNotAllowed: conta suspensa ou desativada.
	ErrUserNotAllowed = errors.New("oidclogin: usuário não pode autenticar")
	// ErrLinkMismatch: o usuário logado agora não é quem iniciou o vínculo.
	ErrLinkMismatch = errors.New("oidclogin: o vínculo foi iniciado por outro usuário")
	// ErrIdentityTaken: esta conta do provedor já está vinculada a outro usuário.
	ErrIdentityTaken = errors.New("oidclogin: conta do provedor já vinculada a outro usuário")
	// ErrUnknownProvider: provedor não configurado.
	ErrUnknownProvider = errors.New("oidclogin: provedor desconhecido")
)

const stateTTL = 10 * time.Minute

// Service orquestra os fluxos de login federado.
type Service struct {
	providers map[string]*Provider
	accounts  Accounts
	eph       ephemeral.Store
	clock     clock.Clock
	log       *slog.Logger
	rand      func([]byte) (int, error)
}

// Option ajusta o Service.
type Option func(*Service)

// WithRand troca a fonte de aleatoriedade (para testes).
func WithRand(f func([]byte) (int, error)) Option { return func(s *Service) { s.rand = f } }

// New cria o serviço com os provedores já descobertos.
func New(providers []*Provider, accounts Accounts, eph ephemeral.Store, clk clock.Clock, log *slog.Logger, opts ...Option) (*Service, error) {
	if accounts == nil || eph == nil || clk == nil {
		return nil, errors.New("oidclogin: dependências obrigatórias ausentes")
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	s := &Service{providers: map[string]*Provider{}, accounts: accounts, eph: eph, clock: clk, log: log}
	for _, p := range providers {
		if _, dup := s.providers[p.name]; dup {
			return nil, fmt.Errorf("oidclogin: provedor %q duplicado", p.name)
		}
		s.providers[p.name] = p
	}
	for _, o := range opts {
		o(s)
	}
	return s, nil
}

// pending é o que guardamos entre o redirecionamento e o callback.
type pending struct {
	Provider    string    `json:"p"`
	Nonce       string    `json:"n"`
	Verifier    string    `json:"v"`
	BindingHash []byte    `json:"b"`
	Intent      Intent    `json:"i"`
	LinkUserID  uuid.UUID `json:"l"`
}

// BeginResult é o que a borda precisa para redirecionar o usuário.
type BeginResult struct {
	// AuthURL é para onde redirecionar o navegador.
	AuthURL string
	// Binding deve ir num cookie curto do navegador (ver BindingCookie) e voltar
	// no callback: prova que quem volta é quem começou.
	Binding string
	// CrossSite: o callback deste provedor é POST cross-site (Apple), então o
	// cookie de binding precisa de SameSite=None.
	CrossSite bool
}

// Begin inicia o fluxo. Para IntentLink, linkUserID é o usuário autenticado.
func (s *Service) Begin(ctx context.Context, provider string, intent Intent, linkUserID uuid.UUID) (BeginResult, error) {
	p, ok := s.providers[provider]
	if !ok {
		return BeginResult{}, ErrUnknownProvider
	}
	switch intent {
	case IntentLogin:
		linkUserID = uuid.Nil
	case IntentLink:
		if linkUserID == uuid.Nil {
			return BeginResult{}, errors.New("oidclogin: IntentLink exige usuário autenticado")
		}
	default:
		return BeginResult{}, fmt.Errorf("oidclogin: intenção desconhecida %q", intent)
	}

	state, stateKey, err := ephemeral.NewToken(s.rand)
	if err != nil {
		return BeginResult{}, err
	}
	nonce, err := randomToken(32, s.rand)
	if err != nil {
		return BeginResult{}, err
	}
	binding, err := randomToken(32, s.rand)
	if err != nil {
		return BeginResult{}, err
	}
	verifier := oauth2.GenerateVerifier()

	bh := sha256.Sum256([]byte(binding))
	raw, err := json.Marshal(pending{
		Provider: p.name, Nonce: nonce, Verifier: verifier,
		BindingHash: bh[:], Intent: intent, LinkUserID: linkUserID,
	})
	if err != nil {
		return BeginResult{}, err
	}
	if err := s.eph.Put(ctx, "oidc:"+stateKey, raw, stateTTL); err != nil {
		return BeginResult{}, err
	}

	// O client_secret não é necessário para montar a URL de autorização.
	opts := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(verifier), oidc.Nonce(nonce)}
	if p.formPost {
		opts = append(opts, oauth2.SetAuthURLParam("response_mode", "form_post"))
	}
	return BeginResult{
		AuthURL:   p.oauthConfig("").AuthCodeURL(state, opts...),
		Binding:   binding,
		CrossSite: p.formPost,
	}, nil
}

// CallbackInput reúne o que chega no callback.
type CallbackInput struct {
	Provider string
	State    string
	Code     string
	// Binding é o valor do cookie de binding lido do navegador.
	Binding string
	// SessionUserID é o usuário autenticado AGORA (uuid.Nil se não há sessão).
	// Obrigatório e conferido para IntentLink.
	SessionUserID uuid.UUID
	// AppleUser é o campo "user" (JSON) que a Apple envia só no primeiro
	// consentimento; usado apenas para o nome de exibição. Opcional.
	AppleUser string
}

// Result é o desfecho de um callback bem-sucedido.
type Result struct {
	User    identity.User
	Intent  Intent
	Created bool // conta nova criada
	Linked  bool // provedor vinculado a conta existente (IntentLink)
}

// Callback conclui o fluxo.
func (s *Service) Callback(ctx context.Context, in CallbackInput) (Result, error) {
	p, ok := s.providers[in.Provider]
	if !ok {
		return Result{}, ErrUnknownProvider
	}
	pend, err := s.takePending(ctx, in, p)
	if err != nil {
		return Result{}, err
	}

	claims, err := s.exchangeAndVerify(ctx, p, in.Code, pend)
	if err != nil {
		s.log.Warn("falha no login federado", slog.String("provedor", p.name), slog.Any("erro", err))
		return Result{}, ErrToken
	}
	issuer := claims.issuer

	// 1) Identidade já conhecida (issuer, subject): é a única base de login.
	existing, err := s.accounts.FindByIdentity(ctx, issuer, claims.subject)
	switch {
	case err == nil:
		if pend.Intent == IntentLink {
			// Já vinculada: se for ao próprio usuário é idempotente; senão, conflito.
			if existing.ID != pend.LinkUserID {
				return Result{}, ErrIdentityTaken
			}
			return Result{User: existing, Intent: IntentLink}, nil
		}
		if !existing.CanLogIn() {
			return Result{}, ErrUserNotAllowed
		}
		return Result{User: existing, Intent: IntentLogin}, nil
	case !errors.Is(err, identity.ErrNotFound):
		return Result{}, err
	}

	// 2) Vincular a um usuário já autenticado.
	if pend.Intent == IntentLink {
		if in.SessionUserID == uuid.Nil || in.SessionUserID != pend.LinkUserID {
			return Result{}, ErrLinkMismatch
		}
		u, err := s.accounts.GetUser(ctx, pend.LinkUserID)
		if err != nil {
			return Result{}, err
		}
		if err := s.accounts.LinkIdentity(ctx, u.ID, issuer, claims.subject, claims.email); err != nil {
			if errors.Is(err, identity.ErrIdentityDup) {
				return Result{}, ErrIdentityTaken
			}
			return Result{}, err
		}
		return Result{User: u, Intent: IntentLink, Linked: true}, nil
	}

	// 3) Conta nova. Exige e-mail verificado pelo provedor.
	if claims.email == "" || !claims.emailVerified {
		return Result{}, ErrEmailUnverified
	}
	email, err := identity.NormalizeEmail(claims.email)
	if err != nil {
		return Result{}, ErrEmailUnverified
	}
	// NUNCA vincular automaticamente por e-mail: quem controla o e-mail no
	// provedor não é, por isso, dono da conta existente com esse e-mail.
	if _, err := s.accounts.GetUserByEmail(ctx, email); err == nil {
		return Result{}, ErrAccountExists
	} else if !errors.Is(err, identity.ErrNotFound) {
		return Result{}, err
	}
	name := claims.name
	if name == "" {
		name = appleDisplayName(in.AppleUser)
	}
	u, err := s.accounts.CreateWithIdentity(ctx, email, sanitizeName(name), true, issuer, claims.subject)
	switch {
	case errors.Is(err, identity.ErrEmailTaken):
		return Result{}, ErrAccountExists // corrida entre duas requisições
	case errors.Is(err, identity.ErrIdentityDup):
		// Outra requisição criou a mesma identidade agora: segue como login.
		u2, ferr := s.accounts.FindByIdentity(ctx, issuer, claims.subject)
		if ferr != nil {
			return Result{}, ferr
		}
		return Result{User: u2, Intent: IntentLogin}, nil
	case err != nil:
		return Result{}, err
	}
	return Result{User: u, Intent: IntentLogin, Created: true}, nil
}

func (s *Service) takePending(ctx context.Context, in CallbackInput, p *Provider) (pending, error) {
	key, err := ephemeral.KeyOf(in.State)
	if err != nil {
		return pending{}, ErrState
	}
	raw, err := s.eph.Take(ctx, "oidc:"+key) // uso único: o state é consumido aqui
	if err != nil {
		return pending{}, ErrState
	}
	var pend pending
	if err := json.Unmarshal(raw, &pend); err != nil {
		return pending{}, ErrState
	}
	got := sha256.Sum256([]byte(in.Binding))
	if in.Binding == "" || subtle.ConstantTimeCompare(got[:], pend.BindingHash) != 1 {
		return pending{}, ErrState
	}
	if pend.Provider != p.name {
		return pending{}, ErrState
	}
	return pend, nil
}

type idClaims struct {
	issuer        string
	subject       string
	email         string
	emailVerified bool
	name          string
}

func (s *Service) exchangeAndVerify(ctx context.Context, p *Provider, code string, pend pending) (idClaims, error) {
	if code == "" {
		return idClaims{}, errors.New("código ausente")
	}
	secret, err := p.secret.Secret(ctx)
	if err != nil {
		return idClaims{}, fmt.Errorf("client_secret: %w", err)
	}
	hctx := ctx
	if p.client != nil {
		hctx = context.WithValue(ctx, oauth2.HTTPClient, p.client)
		hctx = oidc.ClientContext(hctx, p.client)
	}
	tok, err := p.oauthConfig(secret).Exchange(hctx, code, oauth2.VerifierOption(pend.Verifier))
	if err != nil {
		return idClaims{}, fmt.Errorf("troca do código: %w", err)
	}
	rawID, _ := tok.Extra("id_token").(string)
	if rawID == "" {
		return idClaims{}, errors.New("resposta sem id_token")
	}
	idt, err := p.verifier.Verify(hctx, rawID)
	if err != nil {
		return idClaims{}, fmt.Errorf("id_token: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(pend.Nonce)) != 1 {
		return idClaims{}, errors.New("nonce não confere")
	}
	if idt.Subject == "" {
		return idClaims{}, errors.New("id_token sem subject")
	}
	var c struct {
		Email         string `json:"email"`
		EmailVerified any    `json:"email_verified"`
		Name          string `json:"name"`
	}
	if err := idt.Claims(&c); err != nil {
		return idClaims{}, fmt.Errorf("claims: %w", err)
	}
	return idClaims{
		issuer: idt.Issuer, subject: idt.Subject, email: c.Email,
		emailVerified: truthy(c.EmailVerified), name: c.Name,
	}, nil
}

// truthy aceita bool e string "true": a Apple envia email_verified como string.
func truthy(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return strings.EqualFold(x, "true")
	}
	return false
}

// appleDisplayName lê o nome do campo "user" que a Apple envia no primeiro login.
func appleDisplayName(raw string) string {
	if raw == "" {
		return ""
	}
	var u struct {
		Name struct {
			First string `json:"firstName"`
			Last  string `json:"lastName"`
		} `json:"name"`
	}
	if json.Unmarshal([]byte(raw), &u) != nil {
		return ""
	}
	return strings.TrimSpace(u.Name.First + " " + u.Name.Last)
}

// sanitizeName limpa um nome vindo do provedor (dado não confiável): remove
// caracteres de controle e limita a 200 caracteres (limite da coluna).
func sanitizeName(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == utf8.RuneError {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if utf8.RuneCountInString(s) > 200 {
		s = string([]rune(s)[:200])
	}
	return s
}

// --- cookie de binding ---------------------------------------------------------

// BindingCookieName usa o prefixo __Host- (Secure, Path=/, sem Domain).
const BindingCookieName = "__Host-oidc-binding"

// SetBindingCookie grava o cookie de binding. crossSite=true (Apple, form_post)
// usa SameSite=None, senão o navegador não envia o cookie no POST cross-site do
// callback; os demais usam Lax. Validade curta, igual à do state.
func SetBindingCookie(w http.ResponseWriter, value string, crossSite bool) {
	same := http.SameSiteLaxMode
	if crossSite {
		same = http.SameSiteNoneMode
	}
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: SameSite=None é exigido pelo callback form_post cross-site da Apple; o cookie segue Secure, HttpOnly e __Host-
		Name: BindingCookieName, Value: value, Path: "/", Secure: true, HttpOnly: true,
		SameSite: same, MaxAge: int(stateTTL.Seconds()),
	})
}

// ClearBindingCookie remove o cookie após o callback (uso único).
func ClearBindingCookie(w http.ResponseWriter, crossSite bool) {
	same := http.SameSiteLaxMode
	if crossSite {
		same = http.SameSiteNoneMode
	}
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: SameSite=None é exigido pelo callback form_post cross-site da Apple; o cookie segue Secure, HttpOnly e __Host-
		Name: BindingCookieName, Value: "", Path: "/", Secure: true, HttpOnly: true,
		SameSite: same, MaxAge: -1,
	})
}
