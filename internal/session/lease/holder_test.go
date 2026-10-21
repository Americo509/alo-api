package lease

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/zapgateway/zap-gateway/internal/clock"
)

var t0 = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

// cfg: renova a cada 10s, desiste após 15s sem renovar, lease de 30s.
var cfg = Config{TTL: 30 * time.Second, RenewEvery: 10 * time.Second, GiveUpAfter: 15 * time.Second, SafetyDelay: 20 * time.Second}

type env struct {
	clk *clock.Fake
	be  *MemoryBackend
}

func newEnv() env {
	c := clock.NewFake(t0)
	return env{clk: c, be: NewMemoryBackend(c)}
}

func (e env) manager(t *testing.T, owner string) *Manager {
	t.Helper()
	m, err := NewManager(e.be, cfg, e.clk, owner, nil)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// step espera o renovador armar o timer e avança o relógio.
func (e env) step(t *testing.T, d time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := e.clk.BlockUntilWaiters(ctx, 1); err != nil {
		t.Fatalf("renovador não armou o timer: %v", err)
	}
	e.clk.Advance(d)
}

func isLost(h *Holder) bool {
	select {
	case <-h.Lost():
		return true
	default:
		return false
	}
}

func waitLost(t *testing.T, h *Holder) {
	t.Helper()
	select {
	case <-h.Lost():
	case <-time.After(5 * time.Second):
		t.Fatal("posse deveria ter sido perdida")
	}
}

func TestAcquireExcludesSecondOwner(t *testing.T) {
	e := newEnv()
	ctx := context.Background()
	h, err := e.manager(t, "worker-a").Acquire(ctx, "inst-1")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = h.Release(ctx) }()
	if h.Fence().Token != 1 || h.Fence().Owner != "worker-a" {
		t.Fatalf("Fence = %+v", h.Fence())
	}
	if _, err := e.manager(t, "worker-b").Acquire(ctx, "inst-1"); !errors.Is(err, ErrHeld) {
		t.Fatalf("segundo dono: esperava ErrHeld, veio %v", err)
	}
	// Instância diferente não conflita.
	h2, err := e.manager(t, "worker-b").Acquire(ctx, "inst-2")
	if err != nil {
		t.Fatalf("outra instância: %v", err)
	}
	_ = h2.Release(ctx)
}

func TestRenewalKeepsLeaseBeyondTTL(t *testing.T) {
	e := newEnv()
	ctx := context.Background()
	h, err := e.manager(t, "worker-a").Acquire(ctx, "inst-1")
	if err != nil {
		t.Fatal(err)
	}
	for range 10 { // 100s, mais de 3x o TTL
		e.step(t, cfg.RenewEvery)
	}
	if isLost(h) {
		t.Fatalf("posse perdida apesar das renovações: %v", h.Err())
	}
	if _, err := e.manager(t, "worker-b").Acquire(ctx, "inst-1"); !errors.Is(err, ErrHeld) {
		t.Fatalf("lease expirou apesar das renovações: %v", err)
	}
	_ = h.Release(ctx)
}

func TestLostWhenBackendSaysNotOwner(t *testing.T) {
	e := newEnv()
	ctx := context.Background()
	h, _ := e.manager(t, "worker-a").Acquire(ctx, "inst-1")

	// Simula o lease expirado e tomado por outro worker.
	e.be.mu.Lock()
	e.be.leases["inst-1"] = memLease{owner: "worker-b", expires: t0.Add(time.Hour)}
	e.be.mu.Unlock()

	e.step(t, cfg.RenewEvery)
	waitLost(t, h)
	if !errors.Is(h.Err(), ErrLost) {
		t.Fatalf("Err() = %v", h.Err())
	}
}

func TestGivesUpBeforeTTLWhenRedisUnreachable(t *testing.T) {
	e := newEnv()
	ctx := context.Background()
	h, _ := e.manager(t, "worker-a").Acquire(ctx, "inst-1")
	e.be.SetFail(errors.New("redis fora do ar"))

	e.step(t, 10*time.Second)        // t=10s: falha, 10s sem renovar
	e.step(t, 3750*time.Millisecond) // t=13,75s: falha, ainda < 15s
	// Se o renovador rearmou o timer, processou a falha sem desistir.
	wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := e.clk.BlockUntilWaiters(wctx, 1); err != nil || isLost(h) {
		t.Fatalf("desistiu antes de GiveUpAfter (err=%v, perdida=%t)", err, isLost(h))
	}
	e.clk.Advance(3750 * time.Millisecond) // t=17,5s: >= 15s sem renovar
	waitLost(t, h)

	// O dono desistiu em 17,5s; o lease só expira em 30s. Até lá ninguém entra.
	e.be.SetFail(nil)
	if _, err := e.manager(t, "worker-b").Acquire(ctx, "inst-1"); !errors.Is(err, ErrHeld) {
		t.Fatalf("outro worker entrou antes do TTL: %v", err)
	}
	e.clk.Set(t0.Add(cfg.TTL))
	hb, err := e.manager(t, "worker-b").Acquire(ctx, "inst-1")
	if err != nil {
		t.Fatalf("após o TTL o novo dono deveria entrar: %v", err)
	}
	if hb.Fence().Token != 2 {
		t.Fatalf("fencing token do novo dono = %d, quer 2", hb.Fence().Token)
	}
	_ = hb.Release(ctx)
}

func TestReleaseLetsNextOwnerInWithHigherToken(t *testing.T) {
	e := newEnv()
	ctx := context.Background()
	h, _ := e.manager(t, "worker-a").Acquire(ctx, "inst-1")
	if err := h.Release(ctx); err != nil {
		t.Fatal(err)
	}
	if err := h.Release(ctx); err != nil {
		t.Fatalf("segundo Release deveria ser inofensivo: %v", err)
	}
	h2, err := e.manager(t, "worker-b").Acquire(ctx, "inst-1")
	if err != nil {
		t.Fatal(err)
	}
	if h2.Fence().Token <= h.Fence().Token {
		t.Fatalf("token não cresceu: %d -> %d", h.Fence().Token, h2.Fence().Token)
	}
	_ = h2.Release(ctx)
}

func TestReleaseByOldOwnerDoesNotFreeNewOwner(t *testing.T) {
	e := newEnv()
	ctx := context.Background()
	if err := e.be.Release(ctx, "inst-1", "ninguem"); err != nil {
		t.Fatal(err)
	}
	hb, _ := e.manager(t, "worker-b").Acquire(ctx, "inst-1")
	if err := e.be.Release(ctx, "inst-1", "worker-a"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.manager(t, "worker-c").Acquire(ctx, "inst-1"); !errors.Is(err, ErrHeld) {
		t.Fatalf("release de quem não é dono liberou o lease: %v", err)
	}
	_ = hb.Release(ctx)
}

func TestWaitSafe(t *testing.T) {
	e := newEnv()
	ctx := context.Background()
	h, _ := e.manager(t, "worker-a").Acquire(ctx, "inst-1")
	defer func() { _ = h.Release(ctx) }()

	done := make(chan error, 1)
	go func() { done <- h.WaitSafe(ctx) }()

	// Dois timers ativos: renovação e espera de segurança.
	wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := e.clk.BlockUntilWaiters(wctx, 2); err != nil {
		t.Fatal(err)
	}
	e.clk.Advance(cfg.SafetyDelay)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("WaitSafe: %v", err)
		}
	case <-wctx.Done():
		t.Fatal("WaitSafe não retornou após SafetyDelay")
	}
}

func TestWaitSafeAbortsOnLoss(t *testing.T) {
	e := newEnv()
	ctx := context.Background()
	h, _ := e.manager(t, "worker-a").Acquire(ctx, "inst-1")
	e.be.mu.Lock()
	e.be.leases["inst-1"] = memLease{owner: "worker-b", expires: t0.Add(time.Hour)}
	e.be.mu.Unlock()

	done := make(chan error, 1)
	go func() { done <- h.WaitSafe(ctx) }()
	wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := e.clk.BlockUntilWaiters(wctx, 2); err != nil {
		t.Fatal(err)
	}
	e.clk.Advance(cfg.RenewEvery) // renovação descobre a perda antes do SafetyDelay
	select {
	case err := <-done:
		if !errors.Is(err, ErrLost) {
			t.Fatalf("WaitSafe = %v, quer ErrLost", err)
		}
	case <-wctx.Done():
		t.Fatal("WaitSafe não abortou com a perda")
	}
}

func TestConfigValidate(t *testing.T) {
	if err := DefaultConfig().Validate(); err != nil {
		t.Fatalf("DefaultConfig inválida: %v", err)
	}
	bad := []Config{
		{TTL: 0, RenewEvery: 1, GiveUpAfter: 2},
		{TTL: 30 * time.Second, RenewEvery: 15 * time.Second, GiveUpAfter: 15 * time.Second},
		{TTL: 30 * time.Second, RenewEvery: 10 * time.Second, GiveUpAfter: 30 * time.Second},
		{TTL: 30 * time.Second, RenewEvery: 10 * time.Second, GiveUpAfter: 15 * time.Second, SafetyDelay: -1},
	}
	for i, c := range bad {
		if err := c.Validate(); err == nil {
			t.Errorf("config %d inválida foi aceita: %+v", i, c)
		}
	}
	if _, err := NewManager(NewMemoryBackend(clock.NewFake(t0)), cfg, clock.NewFake(t0), "", nil); err == nil {
		t.Error("owner vazio aceito")
	}
}
