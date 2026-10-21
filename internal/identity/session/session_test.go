package session

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/zapgateway/zap-gateway/internal/clock"
)

var (
	ctx = context.Background()
	t0  = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	cfg = Config{Idle: 30 * time.Minute, Absolute: 12 * time.Hour}
)

func newMgr(t *testing.T) (*Manager, *clock.Fake) {
	t.Helper()
	clk := clock.NewFake(t0)
	m, err := NewManager(NewMemoryBackend(clk), cfg, clk)
	if err != nil {
		t.Fatal(err)
	}
	return m, clk
}

func TestCreateAndGet(t *testing.T) {
	m, _ := newMgr(t)
	uid := uuid.New()
	id, d, err := m.Create(ctx, uid, "pwd")
	if err != nil {
		t.Fatal(err)
	}
	if id == "" || d.UserID != uid {
		t.Fatalf("Create devolveu id=%q data=%+v", id, d)
	}
	got, err := m.Get(ctx, id)
	if err != nil || got.UserID != uid {
		t.Fatalf("Get: %+v %v", got, err)
	}
}

func TestIdleExpiry(t *testing.T) {
	m, clk := newMgr(t)
	id, _, _ := m.Create(ctx, uuid.New())

	clk.Advance(29 * time.Minute)
	if _, err := m.Get(ctx, id); err != nil {
		t.Fatalf("sessão expirou antes da inatividade: %v", err)
	}
	// O Get acima deslizou a janela; agora mais 29 min ainda vale.
	clk.Advance(29 * time.Minute)
	if _, err := m.Get(ctx, id); err != nil {
		t.Fatalf("janela de inatividade não deslizou: %v", err)
	}
	// Sem atividade por 30 min, expira.
	clk.Advance(30*time.Minute + time.Second)
	if _, err := m.Get(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("sessão inativa deveria expirar: %v", err)
	}
}

func TestAbsoluteExpiry(t *testing.T) {
	m, clk := newMgr(t)
	id, _, _ := m.Create(ctx, uuid.New())
	// Atividade a cada 20 min não pode furar o teto de 12 h.
	for range 40 {
		clk.Advance(20 * time.Minute)
		_, _ = m.Get(ctx, id)
	}
	if _, err := m.Get(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("sessão passou do limite absoluto: %v", err)
	}
}

func TestRotatePreservesUserAndInvalidatesOld(t *testing.T) {
	m, _ := newMgr(t)
	uid := uuid.New()
	id, _, _ := m.Create(ctx, uid, "pwd")
	newID, d, err := m.Rotate(ctx, id, "mfa")
	if err != nil {
		t.Fatal(err)
	}
	if newID == id {
		t.Fatal("Rotate manteve o mesmo ID")
	}
	if d.UserID != uid {
		t.Fatal("Rotate perdeu o usuário")
	}
	if len(d.AMR) != 2 || d.AMR[0] != "pwd" || d.AMR[1] != "mfa" {
		t.Fatalf("AMR = %v", d.AMR)
	}
	if _, err := m.Get(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Fatal("ID antigo ainda vale após rotação")
	}
	if _, err := m.Get(ctx, newID); err != nil {
		t.Fatalf("ID novo inválido: %v", err)
	}
}

func TestRevoke(t *testing.T) {
	m, _ := newMgr(t)
	id, _, _ := m.Create(ctx, uuid.New())
	if err := m.Revoke(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Get(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Fatal("sessão revogada ainda vale")
	}
	// Revogar de novo, ou revogar ID inválido, é inofensivo.
	if err := m.Revoke(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err := m.Revoke(ctx, "id-invalido"); err != nil {
		t.Fatal(err)
	}
}

func TestRevokeAll(t *testing.T) {
	m, _ := newMgr(t)
	uid := uuid.New()
	var ids []string
	for range 3 {
		id, _, _ := m.Create(ctx, uid)
		ids = append(ids, id)
	}
	// Sessão de outro usuário não é afetada.
	otherID, _, _ := m.Create(ctx, uuid.New())

	if err := m.RevokeAll(ctx, uid); err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		if _, err := m.Get(ctx, id); !errors.Is(err, ErrNotFound) {
			t.Error("sessão do usuário sobreviveu ao RevokeAll")
		}
	}
	if _, err := m.Get(ctx, otherID); err != nil {
		t.Fatalf("RevokeAll atingiu outro usuário: %v", err)
	}
}

func TestGetRejectsTamperedID(t *testing.T) {
	m, _ := newMgr(t)
	id, _, _ := m.Create(ctx, uuid.New())
	// Troca um caractere do ID.
	bad := []byte(id)
	if bad[0] == 'A' {
		bad[0] = 'B'
	} else {
		bad[0] = 'A'
	}
	if _, err := m.Get(ctx, string(bad)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ID adulterado aceito: %v", err)
	}
	for _, bad := range []string{"", "!!!", id + "x"} {
		if _, err := m.Get(ctx, bad); !errors.Is(err, ErrNotFound) {
			t.Errorf("ID inválido %q aceito: %v", bad, err)
		}
	}
}

func TestConfigValidation(t *testing.T) {
	clk := clock.NewFake(t0)
	be := NewMemoryBackend(clk)
	for _, c := range []Config{
		{Idle: time.Second, Absolute: time.Hour},
		{Idle: 2 * time.Hour, Absolute: time.Hour},
		{},
	} {
		if _, err := NewManager(be, c, clk); err == nil {
			t.Errorf("config inválida aceita: %+v", c)
		}
	}
	if _, err := NewManager(nil, DefaultConfig(), clk); err == nil {
		t.Error("backend nil aceito")
	}
}
