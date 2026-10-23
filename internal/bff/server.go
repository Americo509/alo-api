package bff

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"

	"github.com/Americo509/alo-api/internal/audit"
	"github.com/Americo509/alo-api/internal/clock"
	"github.com/Americo509/alo-api/internal/identity"
	"github.com/Americo509/alo-api/internal/identity/ephemeral"
	"github.com/Americo509/alo-api/internal/identity/loginguard"
	"github.com/Americo509/alo-api/internal/identity/oidclogin"
	"github.com/Americo509/alo-api/internal/identity/passkey"
	"github.com/Americo509/alo-api/internal/identity/session"
)

// --- dependências (interfaces definidas por quem consome) --------------------------

// AuthFlow é o fluxo de senha (authflow.Service satisfaz).
type AuthFlow interface {
	Register(ctx context.Context, email, password string) error
	VerifyEmail(ctx context.Context, token string) error
	Login(ctx context.Context, email, password string) (identity.User, bool, error)
	Rehash(ctx context.Context, userID uuid.UUID, password string) error
	VerifyPassword(ctx context.Context, userID uuid.UUID, password string) error
	ChangePassword(ctx context.Context, userID uuid.UUID, current, next string) error
	StartPasswordRecovery(ctx context.Context, email string) error
	CompletePasswordRecovery(ctx context.Context, token, password string) (uuid.UUID, error)
}

// Sessions é o gerenciador de sessões (session.Manager satisfaz).
type Sessions interface {
	CreateWithMeta(ctx context.Context, userID uuid.UUID, meta session.Meta, amr ...string) (string, session.Data, error)
	Get(ctx context.Context, id string) (session.Data, error)
	Rotate(ctx context.Context, oldID string, amr ...string) (string, session.Data, error)
	Revoke(ctx context.Context, id string) error
	RevokeAll(ctx context.Context, userID uuid.UUID) error
	RevokeAllExcept(ctx context.Context, userID uuid.UUID, keepID string) error
	RevokeHandle(ctx context.Context, userID uuid.UUID, handle string) error
	List(ctx context.Context, userID uuid.UUID) ([]session.Info, error)
	Reauth(ctx context.Context, id string, amr ...string) (session.Data, error)
	Fresh(d session.Data, maxAge time.Duration) bool
}

// Users resolve usuários (identity.Repo satisfaz).
type Users interface {
	GetUser(ctx context.Context, id uuid.UUID) (identity.User, error)
}

// MFA é o segundo fator por TOTP e códigos de recuperação (mfa.Service satisfaz).
type MFA interface {
	Enabled(ctx context.Context, userID uuid.UUID) (bool, error)
	BeginEnroll(ctx context.Context, userID uuid.UUID, account string) (string, error)
	ConfirmEnroll(ctx context.Context, userID uuid.UUID, code string) error
	Verify(ctx context.Context, userID uuid.UUID, code string) error
	Disable(ctx context.Context, userID uuid.UUID) error
	GenerateRecoveryCodes(ctx context.Context, userID uuid.UUID) ([]string, error)
	UseRecoveryCode(ctx context.Context, userID uuid.UUID, code string) (int, error)
}

// Passkeys é o WebAuthn (passkey.Service satisfaz).
type Passkeys interface {
	BeginRegistration(ctx context.Context, userID uuid.UUID) (*protocol.CredentialCreation, string, error)
	FinishRegistration(ctx context.Context, userID uuid.UUID, token string, r *http.Request, label string) error
	BeginLogin(ctx context.Context) (*protocol.CredentialAssertion, string, error)
	FinishLogin(ctx context.Context, token string, r *http.Request) (identity.User, error)
	List(ctx context.Context, userID uuid.UUID) ([]passkey.Stored, error)
	Remove(ctx context.Context, userID uuid.UUID, credentialID []byte) error
}

// OIDC é o login federado (oidclogin.Service satisfaz).
type OIDC interface {
	Begin(ctx context.Context, provider string, intent oidclogin.Intent, linkUserID uuid.UUID) (oidclogin.BeginResult, error)
	Callback(ctx context.Context, in oidclogin.CallbackInput) (oidclogin.Result, error)
}

// LoginGuard é a proteção contra força bruta (loginguard.Guard satisfaz).
type LoginGuard interface {
	Check(ctx context.Context, ip, account string) (loginguard.Decision, error)
	Fail(ctx context.Context, ip, account string) error
	Success(ctx context.Context, ip, account string) error
}

// Counter é o contador dos limites por rota (loginguard.Counter satisfaz).
type Counter interface {
	Incr(ctx context.Context, key string, window time.Duration) (int64, error)
}

// Deps reúne as dependências do servidor.
type Deps struct {
	Flow       AuthFlow
	Sessions   Sessions
	Users      Users
	MFA        MFA
	Passkeys   Passkeys
	OIDC       OIDC
	Guard      LoginGuard
	Counter    Counter
	Ephemeral  ephemeral.Store
	Audit      audit.Recorder
	Challenger Challenger // opcional: sem ele, o guard só atrasa
	Clock      clock.Clock
	Log        *slog.Logger
}

// --- configuração ----------------------------------------------------------------------

// Rule é um limite: no máximo Max eventos por Window.
type Rule struct {
	Max    int64
	Window time.Duration
}

// Limits reúne os limites por rota (por IP e, quando há e-mail, por e-mail).
type Limits struct {
	RegisterIP, RegisterEmail Rule
	ForgotIP, ForgotEmail     Rule
	VerifyIP                  Rule
	PasskeyBeginIP            Rule
	MFAIP                     Rule
	OIDCStartIP               Rule
}

// Config configura o servidor.
type Config struct {
	// PublicOrigin é a origem do painel (ex.: https://app.exemplo.com.br). É a
	// única origem aceita em requisições que alteram estado.
	PublicOrigin string
	ExtraOrigins []string

	// Caminhos do SPA para onde o callback do login federado redireciona.
	LoginPath      string // erro no login
	MFAPath        string // segundo fator pendente
	AfterLoginPath string // sucesso
	SecurityPath   string // sucesso ao vincular provedor

	// CSRFKey assina o token CSRF; KeyedHashKey protege chaves de limite
	// derivadas de e-mail. Ambas >= 32 bytes, vindas do cofre de segredos.
	CSRFKey        []byte
	KeyedHashKey   []byte
	TrustedProxies []netip.Prefix

	ReauthMaxAge  time.Duration
	MFAPendingTTL time.Duration
	// ResponseFloor é o tempo mínimo de resposta de cadastro e "esqueci a
	// senha", para não vazar pelo tempo se o e-mail existe.
	ResponseFloor time.Duration
	Limits        Limits
}

// DefaultConfig devolve valores iniciais conservadores.
func DefaultConfig(publicOrigin string, csrfKey, hashKey []byte) Config {
	return Config{
		PublicOrigin:   publicOrigin,
		LoginPath:      "/auth/login",
		MFAPath:        "/auth/mfa",
		AfterLoginPath: "/",
		SecurityPath:   "/settings/security",
		CSRFKey:        csrfKey,
		KeyedHashKey:   hashKey,
		ReauthMaxAge:   10 * time.Minute,
		MFAPendingTTL:  5 * time.Minute,
		ResponseFloor:  400 * time.Millisecond,
		Limits: Limits{
			RegisterIP:     Rule{10, time.Hour},
			RegisterEmail:  Rule{3, time.Hour},
			ForgotIP:       Rule{10, 15 * time.Minute},
			ForgotEmail:    Rule{3, time.Hour},
			VerifyIP:       Rule{30, time.Hour},
			PasskeyBeginIP: Rule{30, 5 * time.Minute},
			MFAIP:          Rule{20, 5 * time.Minute},
			OIDCStartIP:    Rule{30, 5 * time.Minute},
		},
	}
}

func validOrigin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("bff: origem inválida %q", raw)
	}
	loopback := u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1"
	if u.Scheme != "https" && (u.Scheme != "http" || !loopback) {
		return "", fmt.Errorf("bff: a origem %q deve usar https", raw)
	}
	return u.Scheme + "://" + u.Host, nil
}

// Server é o BFF de autenticação.
type Server struct {
	cfg     Config
	d       Deps
	origins map[string]struct{}
	ips     *IPResolver
	log     *slog.Logger
}

// New valida a configuração e cria o servidor.
func New(cfg Config, d Deps) (*Server, error) {
	switch {
	case d.Flow == nil || d.Sessions == nil || d.Users == nil || d.MFA == nil || d.Passkeys == nil ||
		d.OIDC == nil || d.Guard == nil || d.Counter == nil || d.Ephemeral == nil || d.Audit == nil || d.Clock == nil:
		return nil, errors.New("bff: dependências obrigatórias ausentes")
	case len(cfg.CSRFKey) < 32 || len(cfg.KeyedHashKey) < 32:
		return nil, errors.New("bff: CSRFKey e KeyedHashKey precisam de pelo menos 32 bytes")
	case cfg.ReauthMaxAge <= 0 || cfg.MFAPendingTTL <= 0 || cfg.ResponseFloor < 0:
		return nil, errors.New("bff: tempos inválidos")
	}
	origins := map[string]struct{}{}
	for _, o := range append([]string{cfg.PublicOrigin}, cfg.ExtraOrigins...) {
		n, err := validOrigin(o)
		if err != nil {
			return nil, err
		}
		origins[n] = struct{}{}
	}
	log := d.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Server{cfg: cfg, d: d, origins: origins, ips: NewIPResolver(cfg.TrustedProxies), log: log}, nil
}
