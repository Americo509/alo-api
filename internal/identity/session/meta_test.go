package session

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCreateWithMetaAndList(t *testing.T) {
	m, clk := newMgr(t)
	uid := uuid.New()
	id1, _, err := m.CreateWithMeta(ctx, uid, Meta{IP: "203.0.113.7", UserAgent: "Firefox/130"}, "pwd")
	if err != nil {
		t.Fatal(err)
	}
	clk.Advance(time.Minute)
	if _, _, err := m.CreateWithMeta(ctx, uid, Meta{IP: "2001:db8::1", UserAgent: "Chrome"}, "pwd"); err != nil {
		t.Fatal(err)
	}
	// Sessão de outro usuário não aparece.
	if _, _, err := m.CreateWithMeta(ctx, uuid.New(), Meta{IP: "198.51.100.1"}); err != nil {
		t.Fatal(err)
	}

	list, err := m.List(ctx, uid)
	if err != nil || len(list) != 2 {
		t.Fatalf("List = %d sessões (%v)", len(list), err)
	}
	if list[0].IP != "2001:db8::1" || list[1].IP != "203.0.113.7" {
		t.Errorf("ordem (mais recente primeiro) ou IPs errados: %+v", list)
	}
	h1, _ := HandleOf(id1)
	var found bool
	for _, s := range list {
		if s.Handle == h1 && s.UserAgent == "Firefox/130" {
			found = true
		}
	}
	if !found {
		t.Errorf("handle da sessão atual não localizado: %+v", list)
	}
	// O handle não permite reconstruir o ID do cookie.
	if strings.Contains(h1, id1) || h1 == id1 {
		t.Error("o handle expõe o ID da sessão")
	}
}

func TestMetaIsSanitized(t *testing.T) {
	m, _ := newMgr(t)
	uid := uuid.New()
	long := strings.Repeat("é", 500)
	_, d, _ := m.CreateWithMeta(ctx, uid, Meta{IP: "isto não é um ip", UserAgent: "Navegador\r\nX-Injetado: 1\x00" + long}, "pwd")
	if d.IP != "" {
		t.Errorf("IP inválido foi guardado: %q", d.IP)
	}
	if strings.ContainsAny(d.UserAgent, "\r\n\x00") || len([]rune(d.UserAgent)) > maxUserAgent {
		t.Errorf("User-Agent não sanitizado: %q (%d)", d.UserAgent, len([]rune(d.UserAgent)))
	}
}

func TestRevokeHandleOnlyOwnSessions(t *testing.T) {
	m, _ := newMgr(t)
	alice, bob := uuid.New(), uuid.New()
	idA, _, _ := m.CreateWithMeta(ctx, alice, Meta{})
	idB, _, _ := m.CreateWithMeta(ctx, bob, Meta{})
	hA, _ := HandleOf(idA)
	hB, _ := HandleOf(idB)

	// Bob tenta encerrar a sessão da Alice com o handle dela.
	if err := m.RevokeHandle(ctx, bob, hA); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Bob encerrou sessão da Alice: %v", err)
	}
	if _, err := m.Get(ctx, idA); err != nil {
		t.Fatal("a sessão da Alice caiu")
	}
	if err := m.RevokeHandle(ctx, alice, hA); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Get(ctx, idA); !errors.Is(err, ErrNotFound) {
		t.Fatal("sessão encerrada ainda vale")
	}
	if _, err := m.Get(ctx, idB); err != nil {
		t.Fatal("a sessão do Bob caiu")
	}
	for _, bad := range []string{"", "xyz", hB[:63], strings.ToUpper(hB), hB + "0"} {
		if err := m.RevokeHandle(ctx, bob, bad); !errors.Is(err, ErrNotFound) {
			t.Errorf("handle inválido %q: %v", bad, err)
		}
	}
}

func TestRevokeAllExceptKeepsCurrent(t *testing.T) {
	m, _ := newMgr(t)
	uid := uuid.New()
	keep, _, _ := m.CreateWithMeta(ctx, uid, Meta{})
	var others []string
	for range 3 {
		id, _, _ := m.CreateWithMeta(ctx, uid, Meta{})
		others = append(others, id)
	}
	otherUser, _, _ := m.CreateWithMeta(ctx, uuid.New(), Meta{})

	if err := m.RevokeAllExcept(ctx, uid, keep); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Get(ctx, keep); err != nil {
		t.Fatal("a sessão atual caiu")
	}
	for _, id := range others {
		if _, err := m.Get(ctx, id); !errors.Is(err, ErrNotFound) {
			t.Error("outra sessão do usuário sobreviveu")
		}
	}
	if _, err := m.Get(ctx, otherUser); err != nil {
		t.Fatal("RevokeAllExcept atingiu outro usuário")
	}
}

func TestListSkipsExpiredSessions(t *testing.T) {
	m, clk := newMgr(t)
	uid := uuid.New()
	_, _, _ = m.CreateWithMeta(ctx, uid, Meta{})
	clk.Advance(31 * time.Minute) // passou da inatividade
	fresh, _, _ := m.CreateWithMeta(ctx, uid, Meta{})
	list, err := m.List(ctx, uid)
	if err != nil || len(list) != 1 {
		t.Fatalf("List = %d (%v), quer só a sessão viva", len(list), err)
	}
	h, _ := HandleOf(fresh)
	if list[0].Handle != h {
		t.Fatal("listou a sessão errada")
	}
}

func TestReauthAndFresh(t *testing.T) {
	m, clk := newMgr(t)
	id, d, _ := m.CreateWithMeta(ctx, uuid.New(), Meta{}, "pwd")
	if !m.Fresh(d, 10*time.Minute) {
		t.Fatal("login recém-feito deveria ser recente")
	}
	clk.Advance(11 * time.Minute)
	cur, err := m.Get(ctx, id) // atividade mantém a sessão, mas não renova a autenticação
	if err != nil {
		t.Fatal(err)
	}
	if m.Fresh(cur, 10*time.Minute) {
		t.Fatal("atividade comum não pode renovar a autenticação forte")
	}
	after, err := m.Reauth(ctx, id, "mfa")
	if err != nil {
		t.Fatal(err)
	}
	if !m.Fresh(after, 10*time.Minute) {
		t.Fatal("Reauth não renovou a autenticação")
	}
	if len(after.AMR) != 2 || after.AMR[1] != "mfa" {
		t.Errorf("AMR = %v", after.AMR)
	}
	// Sem mexer nas expirações.
	if !after.AbsExpiresAt.Equal(d.AbsExpiresAt) {
		t.Error("Reauth alterou a expiração absoluta")
	}
	if _, err := m.Reauth(ctx, "id-invalido"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Reauth com ID inválido: %v", err)
	}
}

func TestRotateRefreshesAuthAtWhenStrongerFactor(t *testing.T) {
	m, clk := newMgr(t)
	id, _, _ := m.CreateWithMeta(ctx, uuid.New(), Meta{}, "pwd")
	clk.Advance(5 * time.Minute)
	_, d, err := m.Rotate(ctx, id, "mfa")
	if err != nil {
		t.Fatal(err)
	}
	if !d.AuthAt.Equal(clk.Now()) {
		t.Errorf("AuthAt = %v, quer %v", d.AuthAt, clk.Now())
	}
}
