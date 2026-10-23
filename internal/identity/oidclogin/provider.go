// Package oidclogin implementa o login com provedores externos (Google, Apple e
// outros) por OpenID Connect, no padrão mais seguro recomendado hoje
// (RFC 9700, ADR-0007 item 6):
//
//   - Authorization Code com PKCE (S256), state e nonce aleatórios de uso único;
//   - vínculo do callback ao navegador que iniciou o fluxo (cookie de binding),
//     contra login CSRF;
//   - id_token validado: assinatura (JWKS do provedor), emissor, audiência e
//     validade; nonce conferido;
//   - a identidade é o par (issuer, subject) — NUNCA o e-mail;
//   - NUNCA vincula automaticamente a uma conta existente por e-mail (risco de
//     tomada de conta); o vínculo exige o usuário já autenticado.
package oidclogin

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// SecretSource entrega o client_secret do provedor no momento da troca do
// código. Para o Google é um segredo estático (vindo do Vault/KMS); para a
// Apple é um JWT gerado a cada uso (AppleSecret).
type SecretSource interface {
	Secret(ctx context.Context) (string, error)
}

// StaticSecret é um segredo fixo, carregado do cofre de segredos no boot.
type StaticSecret string

func (s StaticSecret) Secret(context.Context) (string, error) { return string(s), nil }

// ProviderConfig configura um provedor OIDC.
type ProviderConfig struct {
	// Name identifica o provedor nas rotas (ex.: "google", "apple").
	Name string
	// Issuer é a URL base do OIDC (descoberta em /.well-known/openid-configuration).
	Issuer   string
	ClientID string
	// RedirectURL é fixo e cadastrado no provedor. Nunca vem da requisição.
	RedirectURL string
	Scopes      []string
	Secret      SecretSource
	// FormPost pede response_mode=form_post (obrigatório na Apple quando se
	// pedem nome/e-mail). O callback chega por POST cross-site.
	FormPost bool
	// HTTPClient opcional (timeouts, testes).
	HTTPClient *http.Client
	// AllowInsecureHTTP permite http:// (só desenvolvimento e testes).
	AllowInsecureHTTP bool
}

// Provider é um provedor já descoberto e pronto para uso.
type Provider struct {
	name     string
	clientID string
	endpoint oauth2.Endpoint
	redirect string
	scopes   []string
	secret   SecretSource
	formPost bool
	verifier *oidc.IDTokenVerifier
	client   *http.Client
}

// Name devolve o nome do provedor.
func (p *Provider) Name() string { return p.name }

// FormPost informa se o callback deste provedor chega por POST cross-site (o
// cookie de binding precisa então ser SameSite=None).
func (p *Provider) FormPost() bool { return p.formPost }

// NewProvider faz a descoberta OIDC e valida a configuração. Falha rápido no
// boot se o provedor estiver inacessível ou mal configurado.
func NewProvider(ctx context.Context, cfg ProviderConfig, now func() time.Time) (*Provider, error) {
	switch {
	case cfg.Name == "" || cfg.Issuer == "" || cfg.ClientID == "" || cfg.RedirectURL == "" || cfg.Secret == nil:
		return nil, errors.New("oidclogin: configuração do provedor incompleta")
	}
	for _, raw := range []string{cfg.Issuer, cfg.RedirectURL} {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return nil, fmt.Errorf("oidclogin: URL inválida %q", raw)
		}
		if u.Scheme != "https" && (u.Scheme != "http" || !cfg.AllowInsecureHTTP) {
			return nil, fmt.Errorf("oidclogin: %q deve usar https", raw)
		}
	}
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "email", "profile"}
	}

	dctx := withClient(ctx, cfg.HTTPClient)
	op, err := oidc.NewProvider(dctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidclogin: descoberta de %s: %w", cfg.Name, err)
	}
	ep := op.Endpoint()
	ep.AuthStyle = oauth2.AuthStyleInParams // client_secret no corpo (exigido pela Apple)

	return &Provider{
		name:     cfg.Name,
		clientID: cfg.ClientID,
		endpoint: ep,
		redirect: cfg.RedirectURL,
		scopes:   scopes,
		secret:   cfg.Secret,
		formPost: cfg.FormPost,
		verifier: op.Verifier(&oidc.Config{ClientID: cfg.ClientID, Now: now}),
		client:   cfg.HTTPClient,
	}, nil
}

func withClient(ctx context.Context, c *http.Client) context.Context {
	if c == nil {
		return ctx
	}
	return oidc.ClientContext(ctx, c)
}

func (p *Provider) oauthConfig(secret string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     p.clientID,
		ClientSecret: secret,
		Endpoint:     p.endpoint,
		RedirectURL:  p.redirect,
		Scopes:       p.scopes,
	}
}

// randomToken devolve n bytes aleatórios em base64 URL-safe sem padding.
func randomToken(n int, randRead func([]byte) (int, error)) (string, error) {
	if randRead == nil {
		randRead = rand.Read
	}
	b := make([]byte, n)
	if _, err := randRead(b); err != nil {
		return "", fmt.Errorf("oidclogin: aleatoriedade: %w", err)
	}
	return encodeB64(b), nil
}
