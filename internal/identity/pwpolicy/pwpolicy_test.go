package pwpolicy

import (
	"context"
	"crypto/sha1" //nolint:gosec // reproduz o formato da API nos testes
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

var ctx = context.Background()

type fakeChecker struct {
	seen int
	err  error
}

func (f fakeChecker) TimesSeen(context.Context, string) (int, error) { return f.seen, f.err }

func TestLength(t *testing.T) {
	p := Policy{MinLength: 12}
	if err := p.Validate(ctx, "curta"); !errors.Is(err, ErrTooShort) {
		t.Errorf("senha curta: %v", err)
	}
	if err := p.Validate(ctx, "doze-caracteres-ok"); err != nil {
		t.Errorf("senha válida recusada: %v", err)
	}
	if err := p.Validate(ctx, strings.Repeat("a", MaxLength+1)); !errors.Is(err, ErrTooLong) {
		t.Errorf("senha longa demais: %v", err)
	}
}

func TestLengthCountsRunesNotBytes(t *testing.T) {
	// 12 emojis = 12 caracteres (48 bytes). Deve passar no mínimo de 12.
	p := Policy{MinLength: 12}
	if err := p.Validate(ctx, strings.Repeat("🔒", 12)); err != nil {
		t.Errorf("12 caracteres multibyte recusados: %v", err)
	}
	if err := p.Validate(ctx, strings.Repeat("🔒", 11)); !errors.Is(err, ErrTooShort) {
		t.Errorf("11 caracteres multibyte deveriam reprovar: %v", err)
	}
}

func TestNoCompositionRules(t *testing.T) {
	// Sem exigência de maiúscula, número ou símbolo (NIST).
	p := Policy{MinLength: 12}
	if err := p.Validate(ctx, "todasminusculas"); err != nil {
		t.Errorf("política impôs regra de composição: %v", err)
	}
}

func TestBreached(t *testing.T) {
	p := Policy{MinLength: 8, Breach: fakeChecker{seen: 42}}
	if err := p.Validate(ctx, "senha-vazada-conhecida"); !errors.Is(err, ErrBreached) {
		t.Errorf("senha vazada aceita: %v", err)
	}
	p.Breach = fakeChecker{seen: 0}
	if err := p.Validate(ctx, "senha-vazada-conhecida"); err != nil {
		t.Errorf("senha não vazada recusada: %v", err)
	}
}

func TestBreachFailOpenAndClosed(t *testing.T) {
	boom := fakeChecker{err: errors.New("serviço fora")}
	open := Policy{MinLength: 8, Breach: boom, FailOpen: true}
	if err := open.Validate(ctx, "senha-qualquer"); err != nil {
		t.Errorf("fail-open deveria aceitar: %v", err)
	}
	closed := Policy{MinLength: 8, Breach: boom, FailOpen: false}
	if err := closed.Validate(ctx, "senha-qualquer"); err == nil {
		t.Error("fail-closed deveria barrar quando o verificador falha")
	}
}

func TestNormalizeNFKC(t *testing.T) {
	// "ﬁ" (ligadura) normaliza para "fi".
	if got := Normalize("aﬁx"); got != "afix" {
		t.Errorf("Normalize = %q", got)
	}
}

// HIBP com k-anonimato: só o prefixo sai; a resposta é comparada localmente.
func TestHIBPKAnonymity(t *testing.T) {
	password := "Password123!"
	sum := sha1.Sum([]byte(password)) //nolint:gosec // reproduz o formato da API
	full := fmt.Sprintf("%X", sum)
	prefix, suffix := full[:5], full[5:]

	var gotPath, gotPadding string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotPadding = r.Header.Get("Add-Padding")
		// Resposta no formato SUFIXO:contagem, com uma linha ruído.
		_, _ = fmt.Fprintf(w, "0000000000000000000000000000000000X:1\r\n%s:1337\r\n", suffix)
	}))
	defer srv.Close()

	h := NewHIBP(srv.Client())
	h.baseURL = srv.URL + "/"
	n, err := h.TimesSeen(ctx, password)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1337 {
		t.Fatalf("TimesSeen = %d, quer 1337", n)
	}
	if gotPath != "/"+prefix {
		t.Errorf("enviou %q; só o prefixo de 5 dígitos deveria sair", gotPath)
	}
	if !strings.Contains(gotPath, prefix) || strings.Contains(gotPath, suffix) {
		t.Error("o sufixo do hash vazou na requisição")
	}
	if gotPadding != "true" {
		t.Error("Add-Padding não foi enviado")
	}
}

func TestHIBPNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1\r\n")
	}))
	defer srv.Close()
	h := NewHIBP(srv.Client())
	h.baseURL = srv.URL + "/"
	n, err := h.TimesSeen(ctx, "qualquer")
	if err != nil || n != 0 {
		t.Fatalf("TimesSeen = %d, %v; quer 0, nil", n, err)
	}
}
