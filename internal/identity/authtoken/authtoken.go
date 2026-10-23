// Package authtoken emite e consome tokens de uso único para verificação de
// e-mail e recuperação de senha (ADR-0007, item 3): 256 bits de crypto/rand,
// guardados só como hash SHA-256, com expiração curta e consumo atômico.
package authtoken

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Americo509/alo-api/internal/clock"
)

// Purpose é a finalidade do token. Um token só vale para a sua finalidade.
type Purpose string

//nolint:gosec // G101: nomes de finalidade, não credenciais
const (
	PurposeEmailVerification Purpose = "verificacao_email"
	PurposePasswordRecovery  Purpose = "recuperacao_senha"
)

// Validade padrão por finalidade.
const (
	emailVerificationTTL = 24 * time.Hour
	passwordRecoveryTTL  = 30 * time.Minute
)

// ErrInvalid cobre token inexistente, de outra finalidade, expirado ou já
// usado. Mensagem única de propósito: não revela qual foi o caso.
var ErrInvalid = errors.New("authtoken: token inválido ou expirado")

var enc = base64.RawURLEncoding

// DB é o mínimo necessário (pool ou transação).
type DB interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Service emite e consome tokens.
type Service struct {
	db    DB
	clock clock.Clock
	rand  func([]byte) (int, error)
}

// Option ajusta o Service.
type Option func(*Service)

// WithRand troca a fonte de aleatoriedade (para testes).
func WithRand(f func([]byte) (int, error)) Option { return func(s *Service) { s.rand = f } }

// New cria o serviço.
func New(db DB, clk clock.Clock, opts ...Option) *Service {
	s := &Service{db: db, clock: clk, rand: rand.Read}
	for _, o := range opts {
		o(s)
	}
	return s
}

// WithDB devolve um Service que usa outra conexão/transação (mesmo relógio e
// fonte de aleatoriedade), para compor com transações de quem chama.
func (s *Service) WithDB(db DB) *Service {
	return &Service{db: db, clock: s.clock, rand: s.rand}
}

func ttlFor(p Purpose) (time.Duration, error) {
	switch p {
	case PurposeEmailVerification:
		return emailVerificationTTL, nil
	case PurposePasswordRecovery:
		return passwordRecoveryTTL, nil
	default:
		return 0, fmt.Errorf("authtoken: finalidade desconhecida %q", p)
	}
}

// Issue cria um token para o usuário e a finalidade e devolve o segredo em
// claro (que vai no link do e-mail e nunca é persistido).
func (s *Service) Issue(ctx context.Context, userID uuid.UUID, p Purpose) (string, error) {
	ttl, err := ttlFor(p)
	if err != nil {
		return "", err
	}
	raw := make([]byte, 32)
	if _, err := s.rand(raw); err != nil {
		return "", fmt.Errorf("authtoken: gerar token: %w", err)
	}
	sum := sha256.Sum256(raw)
	now := s.clock.Now()
	_, err = s.db.Exec(ctx, `
		INSERT INTO ident.auth_tokens (token_hash, user_id, purpose, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5)`,
		sum[:], userID, string(p), now, now.Add(ttl))
	if err != nil {
		return "", fmt.Errorf("authtoken: gravar: %w", err)
	}
	return enc.EncodeToString(raw), nil
}

// Consume valida e invalida o token numa única transação atômica, devolvendo
// o usuário dono. Um token só é aceito uma vez (UPDATE ... WHERE used_at IS
// NULL): chamadas concorrentes com o mesmo token — só uma vence.
func (s *Service) Consume(ctx context.Context, token string, p Purpose) (uuid.UUID, error) {
	raw, err := enc.DecodeString(token)
	if err != nil || len(raw) != 32 {
		return uuid.Nil, ErrInvalid
	}
	sum := sha256.Sum256(raw)
	var userID uuid.UUID
	err = s.db.QueryRow(ctx, `
		UPDATE ident.auth_tokens SET used_at = $2
		WHERE token_hash = $1 AND purpose = $3 AND used_at IS NULL AND expires_at > $2
		RETURNING user_id`,
		sum[:], s.clock.Now(), string(p)).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, ErrInvalid
	} else if err != nil {
		return uuid.Nil, fmt.Errorf("authtoken: consumir: %w", err)
	}
	return userID, nil
}

// InvalidateAll revoga os tokens pendentes de uma finalidade para um usuário.
// Usado ao trocar a senha (invalida recuperações em aberto) e ao emitir um
// novo token do mesmo tipo.
func (s *Service) InvalidateAll(ctx context.Context, userID uuid.UUID, p Purpose) error {
	_, err := s.db.Exec(ctx, `
		UPDATE ident.auth_tokens SET used_at = $3
		WHERE user_id = $1 AND purpose = $2 AND used_at IS NULL`,
		userID, string(p), s.clock.Now())
	return err
}

// DeleteExpired remove tokens expirados ou usados (limpeza periódica).
func (s *Service) DeleteExpired(ctx context.Context) (int64, error) {
	tag, err := s.db.Exec(ctx, `DELETE FROM ident.auth_tokens WHERE expires_at < $1 OR used_at IS NOT NULL`, s.clock.Now())
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
