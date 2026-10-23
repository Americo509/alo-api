//go:build integration

package mfa_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Americo509/alo-api/internal/clock"
	"github.com/Americo509/alo-api/internal/crypto/envelope"
	"github.com/Americo509/alo-api/internal/crypto/envelope/envelopetest"
	"github.com/Americo509/alo-api/internal/identity"
	"github.com/Americo509/alo-api/internal/identity/mfa"
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

var base = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

// platformKey imita a chave de MFA da plataforma (um DEK do envelope).
func platformKey(t *testing.T) *envelope.DataKey {
	t.Helper()
	dk, _, err := envelope.New(envelopetest.New()).GenerateKey(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return dk
}

func newService(t *testing.T, clk *clock.Fake) *mfa.Service {
	t.Helper()
	s, err := mfa.New(db.App, platformKey(t), clk, "ZapGateway")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func newUser(t *testing.T) uuid.UUID {
	t.Helper()
	u, err := identity.NewRepo(db.App).CreateUser(context.Background(), uuid.NewString()+"@example.com", "", true)
	if err != nil {
		t.Fatal(err)
	}
	return u.ID
}

// currentCode calcula o código válido no instante do relógio a partir da
// otpauth URI devolvida pela inscrição.
func currentCode(t *testing.T, uri string, now time.Time) string {
	t.Helper()
	c, err := mfa.CodeForEnrollURI(uri, now)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestEnrollConfirmVerify(t *testing.T) {
	ctx := context.Background()
	clk := clock.NewFake(base)
	s := newService(t, clk)
	uid := newUser(t)

	if on, _ := s.Enabled(ctx, uid); on {
		t.Fatal("usuário novo não deveria ter MFA")
	}
	uri, err := s.BeginEnroll(ctx, uid, "user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	// Antes de confirmar, o fator não vale.
	if err := s.Verify(ctx, uid, currentCode(t, uri, clk.Now())); !errors.Is(err, mfa.ErrNotEnrolled) {
		t.Fatalf("Verify antes de confirmar: %v", err)
	}
	// Código errado na confirmação falha.
	if err := s.ConfirmEnroll(ctx, uid, "000000"); err == nil {
		t.Skip("000000 coincidiu; raro")
	}
	if err := s.ConfirmEnroll(ctx, uid, currentCode(t, uri, clk.Now())); err != nil {
		t.Fatalf("ConfirmEnroll: %v", err)
	}
	if on, _ := s.Enabled(ctx, uid); !on {
		t.Fatal("MFA deveria estar ativo após confirmar")
	}
	// Reinscrever com fator confirmado é recusado.
	if _, err := s.BeginEnroll(ctx, uid, "x"); !errors.Is(err, mfa.ErrAlreadyEnrolled) {
		t.Fatalf("reinscrição: %v", err)
	}

	// Verificação num passo futuro (relógio avança) funciona.
	clk.Advance(60 * time.Second)
	if err := s.Verify(ctx, uid, currentCode(t, uri, clk.Now())); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	// O mesmo código não vale duas vezes (anti-reuso).
	if err := s.Verify(ctx, uid, currentCode(t, uri, clk.Now())); !errors.Is(err, mfa.ErrInvalidCode) {
		t.Fatalf("reuso do código aceito: %v", err)
	}
}

func TestRecoveryCodes(t *testing.T) {
	ctx := context.Background()
	s := newService(t, clock.NewFake(base))
	uid := newUser(t)

	codes, err := s.GenerateRecoveryCodes(ctx, uid)
	if err != nil || len(codes) != 10 {
		t.Fatalf("GenerateRecoveryCodes: %d %v", len(codes), err)
	}
	remaining, err := s.UseRecoveryCode(ctx, uid, codes[0])
	if err != nil || remaining != 9 {
		t.Fatalf("UseRecoveryCode: remaining=%d %v", remaining, err)
	}
	// Uso único.
	if _, err := s.UseRecoveryCode(ctx, uid, codes[0]); !errors.Is(err, mfa.ErrInvalidCode) {
		t.Fatalf("código de recuperação reusado: %v", err)
	}
	// Código inexistente.
	if _, err := s.UseRecoveryCode(ctx, uid, "zzzz-zzzz-zzzz-zzzz"); !errors.Is(err, mfa.ErrInvalidCode) {
		t.Fatalf("código inexistente aceito: %v", err)
	}
	// Regenerar substitui os antigos.
	if _, err := s.GenerateRecoveryCodes(ctx, uid); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UseRecoveryCode(ctx, uid, codes[1]); !errors.Is(err, mfa.ErrInvalidCode) {
		t.Fatal("código antigo ainda vale após regenerar")
	}
}

func TestDisable(t *testing.T) {
	ctx := context.Background()
	clk := clock.NewFake(base)
	s := newService(t, clk)
	uid := newUser(t)
	uri, _ := s.BeginEnroll(ctx, uid, "x@example.com")
	_ = s.ConfirmEnroll(ctx, uid, currentCode(t, uri, clk.Now()))
	_, _ = s.GenerateRecoveryCodes(ctx, uid)

	if err := s.Disable(ctx, uid); err != nil {
		t.Fatal(err)
	}
	if on, _ := s.Enabled(ctx, uid); on {
		t.Fatal("MFA ainda ativo após Disable")
	}
	// Pode inscrever de novo.
	if _, err := s.BeginEnroll(ctx, uid, "x@example.com"); err != nil {
		t.Fatalf("reinscrição após Disable: %v", err)
	}
}

// Segredo de um usuário não abre com o AAD de outro: o Open usa aad(user_id).
func TestSecretBoundToUser(t *testing.T) {
	ctx := context.Background()
	clk := clock.NewFake(base)
	key := platformKey(t)
	s, err := mfa.New(db.App, key, clk, "ZapGateway")
	if err != nil {
		t.Fatal(err)
	}
	uid := newUser(t)
	uri, _ := s.BeginEnroll(ctx, uid, "x@example.com")
	_ = s.ConfirmEnroll(ctx, uid, currentCode(t, uri, clk.Now()))

	// Lê o segredo cifrado direto do banco e tenta abrir com o AAD de outro user.
	var enc []byte
	if err := db.App.QueryRow(ctx, `SELECT secret_enc FROM ident.mfa_totp WHERE user_id=$1`, uid).Scan(&enc); err != nil {
		t.Fatal(err)
	}
	other := uuid.New()
	if _, err := key.Open(enc, append([]byte("mfa-totp:"), other[:]...)); err == nil {
		t.Fatal("segredo abriu com AAD de outro usuário")
	}
}
