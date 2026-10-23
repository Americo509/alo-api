package mfa

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/zapgateway/zap-gateway/internal/clock"
)

var (
	// ErrInvalidCode: código TOTP ou de recuperação inválido.
	ErrInvalidCode = errors.New("mfa: código inválido")
	// ErrNotEnrolled: usuário não tem TOTP confirmado.
	ErrNotEnrolled = errors.New("mfa: segundo fator não configurado")
	// ErrAlreadyEnrolled: já existe TOTP confirmado.
	ErrAlreadyEnrolled = errors.New("mfa: segundo fator já configurado")
)

// Sealer cifra/decifra o segredo TOTP. Em produção é a chave de MFA da
// plataforma (envelope.DataKey); o AAD amarra o segredo ao usuário.
type Sealer interface {
	Seal(plaintext, aad []byte) ([]byte, error)
	Open(sealed, aad []byte) ([]byte, error)
}

// DB é o mínimo necessário (pool ou transação).
type DB interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Service gerencia TOTP e códigos de recuperação.
type Service struct {
	db     DB
	sealer Sealer
	clock  clock.Clock
	issuer string
	rand   func([]byte) (int, error)
}

// Option ajusta o Service.
type Option func(*Service)

// WithRand troca a fonte de aleatoriedade (para testes).
func WithRand(f func([]byte) (int, error)) Option { return func(s *Service) { s.rand = f } }

// New cria o serviço. issuer aparece no app autenticador (ex.: "ZapGateway").
func New(db DB, sealer Sealer, clk clock.Clock, issuer string, opts ...Option) (*Service, error) {
	if db == nil || sealer == nil || clk == nil || issuer == "" {
		return nil, errors.New("mfa: db, sealer, clock e issuer são obrigatórios")
	}
	s := &Service{db: db, sealer: sealer, clock: clk, issuer: issuer, rand: rand.Read}
	for _, o := range opts {
		o(s)
	}
	return s, nil
}

func aad(userID uuid.UUID) []byte { return append([]byte("mfa-totp:"), userID[:]...) }

// BeginEnroll gera um segredo novo (não confirmado) e devolve a otpauth URI
// para o QR. Se já houver TOTP confirmado, recusa. Reiniciar a inscrição antes
// de confirmar sobrescreve o segredo anterior.
func (s *Service) BeginEnroll(ctx context.Context, userID uuid.UUID, account string) (uri string, err error) {
	confirmed, err := s.isConfirmed(ctx, userID)
	if err != nil {
		return "", err
	}
	if confirmed {
		return "", ErrAlreadyEnrolled
	}
	secret := make([]byte, totpSecretLen)
	if _, err := s.rand(secret); err != nil {
		return "", fmt.Errorf("mfa: gerar segredo: %w", err)
	}
	enc, err := s.sealer.Seal(secret, aad(userID))
	if err != nil {
		return "", fmt.Errorf("mfa: cifrar segredo: %w", err)
	}
	_, err = s.db.Exec(ctx, `
		INSERT INTO ident.mfa_totp (user_id, secret_enc, confirmed_at, last_step) VALUES ($1, $2, NULL, 0)
		ON CONFLICT (user_id) DO UPDATE SET secret_enc = excluded.secret_enc, confirmed_at = NULL, last_step = 0
			WHERE ident.mfa_totp.confirmed_at IS NULL`,
		userID, enc)
	if err != nil {
		return "", fmt.Errorf("mfa: gravar inscrição: %w", err)
	}
	return provisioningURI(s.issuer, account, secret), nil
}

// ConfirmEnroll valida o primeiro código e ativa o fator.
func (s *Service) ConfirmEnroll(ctx context.Context, userID uuid.UUID, code string) error {
	secret, _, confirmed, err := s.load(ctx, userID)
	if err != nil {
		return err
	}
	if confirmed {
		return ErrAlreadyEnrolled
	}
	step, ok := verify(secret, code, s.clock.Now(), 0)
	if !ok {
		return ErrInvalidCode
	}
	_, err = s.db.Exec(ctx, `UPDATE ident.mfa_totp SET confirmed_at = $2, last_step = $3 WHERE user_id = $1`,
		userID, s.clock.Now(), step)
	return err
}

// Verify confere um código TOTP de um fator já confirmado e avança last_step
// atomicamente (anti-reuso sob concorrência).
func (s *Service) Verify(ctx context.Context, userID uuid.UUID, code string) error {
	secret, lastStep, confirmed, err := s.load(ctx, userID)
	if err != nil {
		return err
	}
	if !confirmed {
		return ErrNotEnrolled
	}
	step, ok := verify(secret, code, s.clock.Now(), lastStep)
	if !ok {
		return ErrInvalidCode
	}
	// Só aceita se o last_step ainda for o que lemos: duas requisições com o
	// mesmo código — uma só avança.
	tag, err := s.db.Exec(ctx, `UPDATE ident.mfa_totp SET last_step = $3 WHERE user_id = $1 AND last_step = $2`,
		userID, lastStep, step)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrInvalidCode
	}
	return nil
}

// Enabled informa se o usuário tem TOTP confirmado.
func (s *Service) Enabled(ctx context.Context, userID uuid.UUID) (bool, error) {
	return s.isConfirmed(ctx, userID)
}

// Disable remove o TOTP e os códigos de recuperação (exige reautenticação na
// borda, ADR-0007 item 7).
func (s *Service) Disable(ctx context.Context, userID uuid.UUID) error {
	if _, err := s.db.Exec(ctx, `DELETE FROM ident.mfa_totp WHERE user_id = $1`, userID); err != nil {
		return err
	}
	_, err := s.db.Exec(ctx, `DELETE FROM ident.recovery_codes WHERE user_id = $1`, userID)
	return err
}

func (s *Service) load(ctx context.Context, userID uuid.UUID) (secret []byte, lastStep int64, confirmed bool, err error) {
	var enc []byte
	var confirmedAt *time.Time // nil quando NULL (não confirmado)
	err = s.db.QueryRow(ctx, `SELECT secret_enc, last_step, confirmed_at FROM ident.mfa_totp WHERE user_id = $1`, userID).
		Scan(&enc, &lastStep, &confirmedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, 0, false, ErrNotEnrolled
	} else if err != nil {
		return nil, 0, false, err
	}
	secret, err = s.sealer.Open(enc, aad(userID))
	if err != nil {
		return nil, 0, false, fmt.Errorf("mfa: decifrar segredo: %w", err)
	}
	return secret, lastStep, confirmedAt != nil, nil
}

func (s *Service) isConfirmed(ctx context.Context, userID uuid.UUID) (bool, error) {
	var ok bool
	err := s.db.QueryRow(ctx, `SELECT confirmed_at IS NOT NULL FROM ident.mfa_totp WHERE user_id = $1`, userID).Scan(&ok)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return ok, err
}

// --- códigos de recuperação ------------------------------------------------

const (
	recoveryCodeCount = 10
	recoveryCodeBytes = 10 // 80 bits → 16 chars base32
)

// GenerateRecoveryCodes cria um novo conjunto, substituindo o anterior.
// Devolve os códigos em claro UMA vez (para mostrar ao usuário); o banco
// guarda só o hash.
func (s *Service) GenerateRecoveryCodes(ctx context.Context, userID uuid.UUID) ([]string, error) {
	codes := make([]string, recoveryCodeCount)
	hashes := make([][]byte, recoveryCodeCount)
	for i := range codes {
		raw := make([]byte, recoveryCodeBytes)
		if _, err := s.rand(raw); err != nil {
			return nil, err
		}
		codes[i] = formatRecovery(b32.EncodeToString(raw))
		h := sha256.Sum256([]byte(normalizeRecovery(codes[i])))
		hashes[i] = h[:]
	}
	err := func() error {
		if _, err := s.db.Exec(ctx, `DELETE FROM ident.recovery_codes WHERE user_id = $1`, userID); err != nil {
			return err
		}
		_, err := s.db.Exec(ctx, `
			INSERT INTO ident.recovery_codes (user_id, code_hash)
			SELECT $1, h FROM unnest($2::bytea[]) AS h`, userID, hashes)
		return err
	}()
	if err != nil {
		return nil, fmt.Errorf("mfa: gravar códigos de recuperação: %w", err)
	}
	return codes, nil
}

// UseRecoveryCode consome um código (uso único) e devolve quantos restam.
func (s *Service) UseRecoveryCode(ctx context.Context, userID uuid.UUID, code string) (remaining int, err error) {
	h := sha256.Sum256([]byte(normalizeRecovery(code)))
	tag, err := s.db.Exec(ctx, `
		UPDATE ident.recovery_codes SET used_at = $3
		WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL`,
		userID, h[:], s.clock.Now())
	if err != nil {
		return 0, err
	}
	if tag.RowsAffected() == 0 {
		return 0, ErrInvalidCode
	}
	err = s.db.QueryRow(ctx, `SELECT count(*) FROM ident.recovery_codes WHERE user_id = $1 AND used_at IS NULL`, userID).
		Scan(&remaining)
	return remaining, err
}

func formatRecovery(s string) string {
	s = strings.ToLower(s)
	if len(s) >= 8 {
		return s[:4] + "-" + s[4:8] + "-" + s[8:]
	}
	return s
}

func normalizeRecovery(s string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(s), "-", ""))
}
