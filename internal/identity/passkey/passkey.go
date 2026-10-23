// Package passkey implementa login e segundo fator por passkeys (WebAuthn),
// resistentes a phishing (ADR-0007, item 5). Política fixa:
//
//   - credencial descobrível (residente) e verificação do usuário (biometria ou
//     PIN do dispositivo) OBRIGATÓRIAS, para a passkey poder substituir a senha;
//   - atestado "none": não coletamos identidade do fabricante (privacidade);
//   - desafio de uso único, com validade curta, guardado no servidor;
//   - detecção de clonagem pelo contador de assinaturas: autenticador clonado é
//     recusado e a credencial é marcada;
//   - o user handle é o UUID do usuário (opaco, sem dado pessoal).
package passkey

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"github.com/Americo509/alo-api/internal/clock"
	"github.com/Americo509/alo-api/internal/identity"
	"github.com/Americo509/alo-api/internal/identity/ephemeral"
)

var (
	// ErrNotFound: credencial inexistente (ou de outro usuário).
	ErrNotFound = errors.New("passkey: credencial não encontrada")
	// ErrCeremony: desafio inexistente, expirado, já usado ou de outro tipo/usuário.
	ErrCeremony = errors.New("passkey: cerimônia inválida ou expirada")
	// ErrCloned: o contador de assinaturas regrediu; possível autenticador clonado.
	ErrCloned = errors.New("passkey: contador de assinaturas regrediu (possível clone)")
	// ErrUserNotAllowed: conta suspensa/desativada.
	ErrUserNotAllowed = errors.New("passkey: usuário não pode autenticar")
	// ErrLimit: usuário já tem o máximo de passkeys.
	ErrLimit = errors.New("passkey: limite de passkeys por usuário atingido")
	// ErrNotVerified: o autenticador não confirmou a presença/verificação do usuário.
	ErrNotVerified = errors.New("passkey: verificação do usuário não confirmada")
)

// MaxPerUser limita as passkeys por usuário.
const MaxPerUser = 10

const ceremonyTTL = 5 * time.Minute

// Stored é uma credencial persistida.
type Stored struct {
	UserID     uuid.UUID
	Credential webauthn.Credential
	Label      string
	CreatedAt  time.Time
	LastUsedAt time.Time
}

// Credentials é o armazenamento das credenciais (Postgres em produção).
type Credentials interface {
	ListByUser(ctx context.Context, userID uuid.UUID) ([]Stored, error)
	Add(ctx context.Context, userID uuid.UUID, c webauthn.Credential, label string, now time.Time) error
	Find(ctx context.Context, credentialID []byte) (Stored, error) // ErrNotFound
	Update(ctx context.Context, credentialID []byte, c webauthn.Credential, usedAt time.Time) error
	Delete(ctx context.Context, userID uuid.UUID, credentialID []byte) error // ErrNotFound
}

// Users resolve usuários (identity.Repo satisfaz).
type Users interface {
	GetUser(ctx context.Context, id uuid.UUID) (identity.User, error)
}

// Config reúne a identidade do site para o WebAuthn.
type Config struct {
	// RPID é o domínio efetivo (ex.: "app.exemplo.com.br"), sem esquema nem porta.
	RPID string
	// RPDisplayName é o nome mostrado no diálogo do navegador.
	RPDisplayName string
	// RPOrigins são as origens permitidas (ex.: "https://app.exemplo.com.br").
	RPOrigins []string
}

// Service executa as cerimônias.
type Service struct {
	wa    *webauthn.WebAuthn
	creds Credentials
	users Users
	eph   ephemeral.Store
	clock clock.Clock
	log   *slog.Logger
}

// New cria o serviço.
func New(cfg Config, creds Credentials, users Users, eph ephemeral.Store, clk clock.Clock, log *slog.Logger) (*Service, error) {
	if creds == nil || users == nil || eph == nil || clk == nil {
		return nil, errors.New("passkey: dependências obrigatórias ausentes")
	}
	requireRK := true
	wa, err := webauthn.New(&webauthn.Config{
		RPID:                  cfg.RPID,
		RPDisplayName:         cfg.RPDisplayName,
		RPOrigins:             cfg.RPOrigins,
		AttestationPreference: protocol.PreferNoAttestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			RequireResidentKey: &requireRK,
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			UserVerification:   protocol.VerificationRequired,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("passkey: configurar WebAuthn: %w", err)
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Service{wa: wa, creds: creds, users: users, eph: eph, clock: clk, log: log}, nil
}

// --- usuário para a biblioteca ----------------------------------------------

type waUser struct {
	id    uuid.UUID
	name  string
	disp  string
	creds []webauthn.Credential
}

func (u waUser) WebAuthnID() []byte                         { return u.id[:] }
func (u waUser) WebAuthnName() string                       { return u.name }
func (u waUser) WebAuthnDisplayName() string                { return u.disp }
func (u waUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func (s *Service) loadUser(ctx context.Context, id uuid.UUID) (waUser, identity.User, error) {
	u, err := s.users.GetUser(ctx, id)
	if err != nil {
		return waUser{}, identity.User{}, err
	}
	stored, err := s.creds.ListByUser(ctx, id)
	if err != nil {
		return waUser{}, identity.User{}, err
	}
	cs := make([]webauthn.Credential, len(stored))
	for i, st := range stored {
		cs[i] = st.Credential
	}
	disp := u.DisplayName
	if disp == "" {
		disp = u.Email
	}
	return waUser{id: u.ID, name: u.Email, disp: disp, creds: cs}, u, nil
}

// --- estado da cerimônia ------------------------------------------------------

type ceremony struct {
	Kind    string               `json:"k"` // "reg" ou "login"
	UserID  uuid.UUID            `json:"u"`
	Session webauthn.SessionData `json:"s"`
}

const (
	kindRegistration = "reg"
	kindLogin        = "login"
)

func (s *Service) saveCeremony(ctx context.Context, c ceremony) (string, error) {
	token, key, err := ephemeral.NewToken(nil)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	if err := s.eph.Put(ctx, "passkey:"+key, raw, ceremonyTTL); err != nil {
		return "", err
	}
	return token, nil
}

func (s *Service) takeCeremony(ctx context.Context, token, kind string) (ceremony, error) {
	key, err := ephemeral.KeyOf(token)
	if err != nil {
		return ceremony{}, ErrCeremony
	}
	raw, err := s.eph.Take(ctx, "passkey:"+key)
	if err != nil {
		return ceremony{}, ErrCeremony
	}
	var c ceremony
	if err := json.Unmarshal(raw, &c); err != nil || c.Kind != kind {
		return ceremony{}, ErrCeremony
	}
	return c, nil
}

// --- registro -----------------------------------------------------------------

// BeginRegistration inicia o cadastro de uma passkey para um usuário JÁ
// autenticado. Devolve as opções (JSON para o navegador) e o token da cerimônia.
func (s *Service) BeginRegistration(ctx context.Context, userID uuid.UUID) (*protocol.CredentialCreation, string, error) {
	wu, u, err := s.loadUser(ctx, userID)
	if err != nil {
		return nil, "", err
	}
	if !u.CanLogIn() {
		return nil, "", ErrUserNotAllowed
	}
	if len(wu.creds) >= MaxPerUser {
		return nil, "", ErrLimit
	}
	creation, session, err := s.wa.BeginRegistration(wu,
		webauthn.WithExclusions(webauthn.Credentials(wu.creds).CredentialDescriptors()))
	if err != nil {
		return nil, "", fmt.Errorf("passkey: iniciar registro: %w", err)
	}
	token, err := s.saveCeremony(ctx, ceremony{Kind: kindRegistration, UserID: userID, Session: *session})
	if err != nil {
		return nil, "", err
	}
	return creation, token, nil
}

// FinishRegistration conclui o cadastro lendo a resposta do navegador no corpo
// da requisição. Só aceita a cerimônia iniciada para o MESMO usuário.
func (s *Service) FinishRegistration(ctx context.Context, userID uuid.UUID, token string, r *http.Request, label string) error {
	c, err := s.takeCeremony(ctx, token, kindRegistration)
	if err != nil {
		return err
	}
	if c.UserID != userID {
		return ErrCeremony
	}
	wu, _, err := s.loadUser(ctx, userID)
	if err != nil {
		return err
	}
	if len(wu.creds) >= MaxPerUser {
		return ErrLimit
	}
	cred, err := s.wa.FinishRegistration(wu, c.Session, r)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrCeremony, err)
	}
	if !cred.Flags.UserVerified {
		return ErrNotVerified
	}
	return s.creds.Add(ctx, userID, *cred, label, s.clock.Now())
}

// --- login --------------------------------------------------------------------

// BeginLogin inicia um login sem identificar o usuário antes (a passkey
// descobrível diz quem é). Devolve as opções e o token da cerimônia.
func (s *Service) BeginLogin(ctx context.Context) (*protocol.CredentialAssertion, string, error) {
	assertion, session, err := s.wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		return nil, "", fmt.Errorf("passkey: iniciar login: %w", err)
	}
	token, err := s.saveCeremony(ctx, ceremony{Kind: kindLogin, Session: *session})
	if err != nil {
		return nil, "", err
	}
	return assertion, token, nil
}

// FinishLogin valida a assinatura e devolve o usuário autenticado. Falhas de
// autenticação devolvem sempre ErrCeremony (ou ErrCloned/ErrUserNotAllowed),
// sem detalhar o motivo ao cliente.
func (s *Service) FinishLogin(ctx context.Context, token string, r *http.Request) (identity.User, error) {
	c, err := s.takeCeremony(ctx, token, kindLogin)
	if err != nil {
		return identity.User{}, err
	}

	var (
		loaded identity.User
		stored Stored
	)
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		st, err := s.creds.Find(ctx, rawID)
		if err != nil {
			return nil, err
		}
		// O user handle informado pelo autenticador tem de ser o dono da credencial.
		if !bytes.Equal(userHandle, st.UserID[:]) {
			return nil, errors.New("user handle não pertence à credencial")
		}
		wu, u, err := s.loadUser(ctx, st.UserID)
		if err != nil {
			return nil, err
		}
		loaded, stored = u, st
		return wu, nil
	}
	cred, err := s.wa.FinishDiscoverableLogin(handler, c.Session, r)
	if err != nil {
		return identity.User{}, fmt.Errorf("%w: %w", ErrCeremony, err)
	}

	now := s.clock.Now()
	if cred.Authenticator.CloneWarning {
		// Persiste o aviso (e o contador) e recusa o login.
		_ = s.creds.Update(ctx, cred.ID, *cred, now)
		s.log.Warn("possível passkey clonada: contador regrediu",
			slog.String("user_id", stored.UserID.String()))
		return identity.User{}, ErrCloned
	}
	if !cred.Flags.UserVerified {
		return identity.User{}, ErrNotVerified
	}
	if !loaded.CanLogIn() {
		return identity.User{}, ErrUserNotAllowed
	}
	if err := s.creds.Update(ctx, cred.ID, *cred, now); err != nil {
		return identity.User{}, err
	}
	return loaded, nil
}

// --- gestão -------------------------------------------------------------------

// List devolve as passkeys do usuário (para a tela de segurança).
func (s *Service) List(ctx context.Context, userID uuid.UUID) ([]Stored, error) {
	return s.creds.ListByUser(ctx, userID)
}

// Remove apaga uma passkey do usuário. A borda deve exigir reautenticação.
func (s *Service) Remove(ctx context.Context, userID uuid.UUID, credentialID []byte) error {
	return s.creds.Delete(ctx, userID, credentialID)
}
