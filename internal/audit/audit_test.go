package audit

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Americo509/alo-api/internal/clock"
)

var (
	ctx = context.Background()
	t0  = time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
)

func TestSanitizeLimitsAndStripsControl(t *testing.T) {
	meta := map[string]string{}
	for i := range 20 {
		meta[strings.Repeat("k", 50)+string(rune('a'+i))] = strings.Repeat("v", 500)
	}
	e := Sanitize(Event{
		Type: LoginFailure, IP: "203.0.113.7\r\nX: y",
		UserAgent: "UA\x00" + strings.Repeat("é", 500), Meta: meta,
	})
	if strings.ContainsAny(e.IP, "\r\n") || strings.ContainsAny(e.UserAgent, "\x00") {
		t.Errorf("caracteres de controle: ip=%q ua=%q", e.IP, e.UserAgent)
	}
	if len([]rune(e.UserAgent)) > maxUA {
		t.Errorf("UA com %d caracteres", len([]rune(e.UserAgent)))
	}
	if len(e.Meta) > maxMetaEntries {
		t.Errorf("Meta com %d entradas", len(e.Meta))
	}
	for k, v := range e.Meta {
		if len([]rune(k)) > maxMetaKey || len([]rune(v)) > maxMetaValue {
			t.Errorf("entrada grande demais: %d/%d", len([]rune(k)), len([]rune(v)))
		}
	}
}

func TestMemoryRecordAndRecent(t *testing.T) {
	clk := clock.NewFake(t0)
	m := NewMemory(clk)
	alice, bob := uuid.New(), uuid.New()
	_ = m.Record(ctx, Event{Type: LoginSuccess, UserID: alice, IP: "203.0.113.1"})
	clk.Advance(time.Minute)
	_ = m.Record(ctx, Event{Type: LoginFailure, UserID: bob})
	clk.Advance(time.Minute)
	_ = m.Record(ctx, Event{Type: PasswordChanged, UserID: alice})
	_ = m.Record(ctx, Event{Type: LoginFailure}) // sem usuário (e-mail inexistente)

	got, _ := m.RecentByUser(ctx, alice, 10)
	if len(got) != 2 || got[0].Type != PasswordChanged || got[1].Type != LoginSuccess {
		t.Fatalf("RecentByUser = %+v (esperado mais novo primeiro, só da Alice)", got)
	}
	if got, _ := m.RecentByUser(ctx, alice, 1); len(got) != 1 {
		t.Fatalf("limite ignorado: %d", len(got))
	}
	if !got[0].At.Equal(t0.Add(2 * time.Minute)) {
		t.Errorf("At = %v", got[0].At)
	}
	if len(m.OfType(LoginFailure)) != 2 {
		t.Errorf("OfType(LoginFailure) = %d", len(m.OfType(LoginFailure)))
	}
}

func TestMemoryRetention(t *testing.T) {
	clk := clock.NewFake(t0)
	m := NewMemory(clk)
	_ = m.Record(ctx, Event{Type: LoginSuccess})
	clk.Advance(200 * 24 * time.Hour)
	_ = m.Record(ctx, Event{Type: LoginSuccess})

	n, err := m.DeleteOlderThan(ctx, clk.Now().Add(-183*24*time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("DeleteOlderThan = %d, %v", n, err)
	}
	if len(m.All()) != 1 {
		t.Fatalf("restaram %d eventos", len(m.All()))
	}
}

func TestNoop(t *testing.T) {
	if err := (Noop{}).Record(ctx, Event{Type: Logout}); err != nil {
		t.Fatal(err)
	}
}
