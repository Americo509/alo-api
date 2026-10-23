//go:build integration

package authtoken_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Americo509/alo-api/internal/clock"
	"github.com/Americo509/alo-api/internal/identity"
	"github.com/Americo509/alo-api/internal/identity/authtoken"
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

var t0 = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

func newUser(t *testing.T) uuid.UUID {
	t.Helper()
	u, err := identity.NewRepo(db.App).CreateUser(context.Background(), uuid.NewString()+"@example.com", "", false)
	if err != nil {
		t.Fatal(err)
	}
	return u.ID
}

func TestIssueAndConsume(t *testing.T) {
	ctx := context.Background()
	clk := clock.NewFake(t0)
	svc := authtoken.New(db.App, clk)
	uid := newUser(t)

	tok, err := svc.Issue(ctx, uid, authtoken.PurposeEmailVerification)
	if err != nil || tok == "" {
		t.Fatalf("Issue: %q %v", tok, err)
	}
	got, err := svc.Consume(ctx, tok, authtoken.PurposeEmailVerification)
	if err != nil || got != uid {
		t.Fatalf("Consume: %v %v", got, err)
	}
	// Uso único: a segunda vez falha.
	if _, err := svc.Consume(ctx, tok, authtoken.PurposeEmailVerification); !errors.Is(err, authtoken.ErrInvalid) {
		t.Fatalf("token reusado aceito: %v", err)
	}
}

func TestWrongPurposeRejected(t *testing.T) {
	ctx := context.Background()
	svc := authtoken.New(db.App, clock.NewFake(t0))
	uid := newUser(t)
	tok, _ := svc.Issue(ctx, uid, authtoken.PurposePasswordRecovery)
	if _, err := svc.Consume(ctx, tok, authtoken.PurposeEmailVerification); !errors.Is(err, authtoken.ErrInvalid) {
		t.Fatalf("token usado com finalidade errada: %v", err)
	}
	// Com a finalidade certa, funciona.
	if _, err := svc.Consume(ctx, tok, authtoken.PurposePasswordRecovery); err != nil {
		t.Fatalf("finalidade certa falhou: %v", err)
	}
}

func TestExpiry(t *testing.T) {
	ctx := context.Background()
	clk := clock.NewFake(t0)
	svc := authtoken.New(db.App, clk)
	uid := newUser(t)
	tok, _ := svc.Issue(ctx, uid, authtoken.PurposePasswordRecovery)

	clk.Advance(31 * time.Minute) // recuperação expira em 30 min
	if _, err := svc.Consume(ctx, tok, authtoken.PurposePasswordRecovery); !errors.Is(err, authtoken.ErrInvalid) {
		t.Fatalf("token expirado aceito: %v", err)
	}
}

func TestInvalidateAll(t *testing.T) {
	ctx := context.Background()
	svc := authtoken.New(db.App, clock.NewFake(t0))
	uid := newUser(t)
	t1, _ := svc.Issue(ctx, uid, authtoken.PurposePasswordRecovery)
	t2, _ := svc.Issue(ctx, uid, authtoken.PurposePasswordRecovery)
	keep, _ := svc.Issue(ctx, uid, authtoken.PurposeEmailVerification)

	if err := svc.InvalidateAll(ctx, uid, authtoken.PurposePasswordRecovery); err != nil {
		t.Fatal(err)
	}
	for _, tok := range []string{t1, t2} {
		if _, err := svc.Consume(ctx, tok, authtoken.PurposePasswordRecovery); !errors.Is(err, authtoken.ErrInvalid) {
			t.Error("token de recuperação sobreviveu ao InvalidateAll")
		}
	}
	// Token de outra finalidade não é afetado.
	if _, err := svc.Consume(ctx, keep, authtoken.PurposeEmailVerification); err != nil {
		t.Fatalf("InvalidateAll atingiu outra finalidade: %v", err)
	}
}

func TestConsumeRejectsGarbage(t *testing.T) {
	ctx := context.Background()
	svc := authtoken.New(db.App, clock.NewFake(t0))
	for _, bad := range []string{"", "!!!", "YWJj"} {
		if _, err := svc.Consume(ctx, bad, authtoken.PurposeEmailVerification); !errors.Is(err, authtoken.ErrInvalid) {
			t.Errorf("lixo %q aceito: %v", bad, err)
		}
	}
}

func TestDeleteExpired(t *testing.T) {
	ctx := context.Background()
	clk := clock.NewFake(t0)
	svc := authtoken.New(db.App, clk)
	uid := newUser(t)
	_, _ = svc.Issue(ctx, uid, authtoken.PurposePasswordRecovery)
	used, _ := svc.Issue(ctx, uid, authtoken.PurposeEmailVerification)
	_, _ = svc.Consume(ctx, used, authtoken.PurposeEmailVerification)

	clk.Advance(48 * time.Hour)
	n, err := svc.DeleteExpired(ctx)
	if err != nil || n < 2 {
		t.Fatalf("DeleteExpired removeu %d (%v)", n, err)
	}
}
