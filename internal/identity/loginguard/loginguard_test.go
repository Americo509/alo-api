package loginguard

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/Americo509/alo-api/internal/clock"
)

var (
	ctx = context.Background()
	t0  = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
)

func newGuard(t *testing.T, cfg Config) (*Guard, *clock.Fake) {
	t.Helper()
	clk := clock.NewFake(t0)
	g, err := New(NewMemoryCounter(clk), cfg, clk)
	if err != nil {
		t.Fatal(err)
	}
	return g, clk
}

var cfg = Config{
	Window: 15 * time.Minute, DelayAfter: 3, DelayStep: 500 * time.Millisecond, MaxDelay: 5 * time.Second,
	ChallengeAfter: 5, BlockAfterIP: 10, GlobalWindow: time.Minute, GlobalStuffingThreshold: 100,
}

const (
	ip   = "203.0.113.7"
	acct = "hash-da-conta"
)

func TestCleanStartAllows(t *testing.T) {
	g, _ := newGuard(t, cfg)
	d, err := g.Check(ctx, ip, acct)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Allow || d.Delay != 0 || d.Challenge {
		t.Fatalf("início limpo: %+v", d)
	}
}

func TestProgressiveDelay(t *testing.T) {
	g, _ := newGuard(t, cfg)
	// 3 falhas: ainda sem atraso (DelayAfter=3 significa atraso a partir da 3ª+1).
	for range 3 {
		fail(t, g)
	}
	d, _ := g.Check(ctx, ip, acct)
	if d.Delay != cfg.DelayStep {
		t.Fatalf("após 3 falhas, atraso = %v, quer %v", d.Delay, cfg.DelayStep)
	}
	fail(t, g) // 4ª
	d, _ = g.Check(ctx, ip, acct)
	if d.Delay != 2*cfg.DelayStep {
		t.Fatalf("após 4 falhas, atraso = %v", d.Delay)
	}
}

func TestDelayCap(t *testing.T) {
	// Bloqueio de IP alto para o atraso ter espaço de chegar ao teto.
	cfgHiBlock := cfg
	cfgHiBlock.BlockAfterIP = 1000
	g, _ := newGuard(t, cfgHiBlock)
	// Teto = MaxDelay/DelayStep = 10 passos → precisa de >= 12 falhas.
	for range 20 {
		fail(t, g)
	}
	d, _ := g.Check(ctx, ip, acct)
	if d.Delay != cfg.MaxDelay {
		t.Fatalf("atraso não respeitou o teto: %v", d.Delay)
	}
}

func TestChallengeAfterThreshold(t *testing.T) {
	g, _ := newGuard(t, cfg)
	for range 4 {
		fail(t, g)
	}
	if d, _ := g.Check(ctx, ip, acct); d.Challenge {
		t.Fatal("desafio antes do limiar")
	}
	fail(t, g) // 5ª
	if d, _ := g.Check(ctx, ip, acct); !d.Challenge {
		t.Fatal("desafio deveria estar ativo no limiar")
	}
}

func TestIPBlockButNotAccountLockout(t *testing.T) {
	g, _ := newGuard(t, cfg)
	for range 10 {
		fail(t, g)
	}
	d, _ := g.Check(ctx, ip, acct)
	if d.Allow {
		t.Fatal("IP com muitas falhas deveria ser bloqueado temporariamente")
	}
	if d.RetryAfter <= 0 {
		t.Fatal("bloqueio deve informar RetryAfter")
	}
	// A MESMA conta de outro IP continua podendo tentar (sem lockout de conta).
	d2, _ := g.Check(ctx, "198.51.100.9", acct)
	if !d2.Allow {
		t.Fatalf("conta travada por falhas de outro IP (lockout indevido): %+v", d2)
	}
}

func TestSuccessResetsAccountButNotIP(t *testing.T) {
	g, _ := newGuard(t, cfg)
	for range 4 {
		fail(t, g)
	}
	if err := g.Success(ctx, ip, acct); err != nil {
		t.Fatal(err)
	}
	// A conta esfriou: de outro IP, está limpa.
	if d, _ := g.Check(ctx, "198.51.100.9", acct); d.Delay != 0 || d.Challenge {
		t.Fatalf("Success não zerou o contador da conta: %+v", d)
	}
	// O IP NÃO esfriou: um atacante com conta própria não zera o limite do IP
	// alternando logins válidos.
	if d, _ := g.Check(ctx, ip, "outra-conta"); d.Delay == 0 {
		t.Fatalf("Success zerou o contador do IP: %+v", d)
	}
}

func TestWindowCools(t *testing.T) {
	g, clk := newGuard(t, cfg)
	for range 4 {
		fail(t, g)
	}
	clk.Advance(16 * time.Minute) // além da janela
	d, _ := g.Check(ctx, ip, acct)
	if d.Delay != 0 {
		t.Fatalf("contadores não esfriaram após a janela: %+v", d)
	}
}

func TestGlobalStuffingTriggersChallengeForAll(t *testing.T) {
	cfgLowGlobal := cfg
	cfgLowGlobal.GlobalStuffingThreshold = 5
	g, _ := newGuard(t, cfgLowGlobal)
	// Falhas distribuídas em contas/IPs diferentes (nenhuma passa do limiar
	// individual), mas o contador global dispara.
	for i := range 5 {
		_ = g.Fail(ctx, ipN(i), acctN(i))
	}
	// Uma conta novinha, sem falhas próprias, já exige desafio.
	d, _ := g.Check(ctx, "nova-ip", "nova-conta")
	if !d.Challenge {
		t.Fatal("pico global de falhas deveria exigir desafio para todos")
	}
	if !d.Allow {
		t.Fatal("stuffing global não deve bloquear contas legítimas, só desafiar")
	}
}

func TestConfigValidation(t *testing.T) {
	clk := clock.NewFake(t0)
	c := NewMemoryCounter(clk)
	for _, bad := range []Config{
		{},
		{Window: time.Minute, DelayAfter: 0, ChallengeAfter: 1, BlockAfterIP: 1, GlobalWindow: time.Minute},
		{Window: time.Minute, DelayAfter: 1, ChallengeAfter: 1, BlockAfterIP: 1, GlobalWindow: 0},
	} {
		if _, err := New(c, bad, clk); err == nil {
			t.Errorf("config inválida aceita: %+v", bad)
		}
	}
}

func fail(t *testing.T, g *Guard) {
	t.Helper()
	if err := g.Fail(ctx, ip, acct); err != nil {
		t.Fatal(err)
	}
}

func ipN(i int) string   { return "ip-" + strconv.Itoa(i) }
func acctN(i int) string { return "acct-" + strconv.Itoa(i) }
