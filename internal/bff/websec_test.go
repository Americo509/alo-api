package bff

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

// --- IP do cliente -----------------------------------------------------------------------

func req(remote, xff string) *http.Request {
	r := httptest.NewRequestWithContext(ctx, http.MethodGet, "/", nil)
	r.RemoteAddr = remote
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	return r
}

func prefixes(t *testing.T, ps ...string) []netip.Prefix {
	t.Helper()
	var out []netip.Prefix
	for _, p := range ps {
		out = append(out, netip.MustParsePrefix(p))
	}
	return out
}

func TestIPFromUntrustedPeerIgnoresForwardedHeader(t *testing.T) {
	r := NewIPResolver(nil)
	// Sem proxy confiável, X-Forwarded-For é só um cabeçalho que o cliente forjou.
	if got := r.From(req("203.0.113.9:4444", "1.2.3.4")); got != "203.0.113.9" {
		t.Fatalf("IP = %q; o cabeçalho forjado foi aceito", got)
	}
	r = NewIPResolver(prefixes(t, "10.0.0.0/8"))
	if got := r.From(req("203.0.113.9:4444", "1.2.3.4")); got != "203.0.113.9" {
		t.Fatalf("IP = %q; peer não confiável não pode ditar o IP", got)
	}
}

func TestIPFromTrustedProxyTakesRightmostUntrusted(t *testing.T) {
	r := NewIPResolver(prefixes(t, "10.0.0.0/8"))
	// O cliente forjou "6.6.6.6"; o proxy confiável acrescentou o IP real (198.51.100.7).
	// Cadeia: forjado, real, proxy interno.
	if got := r.From(req("10.0.0.5:80", "6.6.6.6, 198.51.100.7, 10.0.0.9")); got != "198.51.100.7" {
		t.Fatalf("IP = %q, quer o primeiro NÃO confiável da direita (198.51.100.7)", got)
	}
	if got := r.From(req("10.0.0.5:80", "198.51.100.7")); got != "198.51.100.7" {
		t.Fatalf("IP = %q", got)
	}
}

func TestIPFromTrustedProxyFallbacks(t *testing.T) {
	r := NewIPResolver(prefixes(t, "10.0.0.0/8"))
	if got := r.From(req("10.0.0.5:80", "")); got != "10.0.0.5" {
		t.Errorf("sem cabeçalho: %q", got)
	}
	if got := r.From(req("10.0.0.5:80", "lixo, 198.51.100.7")); got != "198.51.100.7" {
		// "lixo" está à esquerda do primeiro não confiável da direita; não é lido.
		t.Errorf("lixo à esquerda: %q", got)
	}
	if got := r.From(req("10.0.0.5:80", "198.51.100.7, lixo")); got != "10.0.0.5" {
		t.Errorf("cabeçalho malformado à direita deveria cair para o peer: %q", got)
	}
	if got := r.From(req("10.0.0.5:80", "10.1.1.1, 10.2.2.2")); got != "10.0.0.5" {
		t.Errorf("cadeia só de confiáveis: %q", got)
	}
}

func TestIPNormalization(t *testing.T) {
	r := NewIPResolver(nil)
	if got := r.From(req("[::ffff:203.0.113.9]:80", "")); got != "203.0.113.9" {
		t.Errorf("IPv4 mapeado em IPv6: %q", got)
	}
	if got := r.From(req("sem-porta-nem-ip", "")); got != "" {
		t.Errorf("RemoteAddr inválido: %q", got)
	}
}

func TestRateKeyBucketsIPv6By64(t *testing.T) {
	a := rateKey("2001:db8:1:2:aaaa:bbbb:cccc:dddd")
	b := rateKey("2001:db8:1:2:1111:2222:3333:4444")
	c := rateKey("2001:db8:1:3::1")
	if a != b {
		t.Errorf("mesmo /64 gerou chaves diferentes: %q %q", a, b)
	}
	if a == c {
		t.Error("/64 diferentes colidiram")
	}
	if rateKey("203.0.113.9") != "203.0.113.9" {
		t.Error("IPv4 não deveria ser agrupado")
	}
	if rateKey("::ffff:203.0.113.9") != "203.0.113.9" {
		t.Error("IPv4 mapeado deveria virar IPv4")
	}
	if rateKey("lixo") != "desconhecido" {
		t.Error("IP inválido")
	}
}

// --- cabeçalhos de segurança ---------------------------------------------------------------

func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	e := newEnv(t)
	c := e.client(t)
	want := map[string]string{
		"Cache-Control":              "no-store",
		"X-Content-Type-Options":     "nosniff",
		"Referrer-Policy":            "no-referrer",
		"X-Frame-Options":            "DENY",
		"Cross-Origin-Opener-Policy": "same-origin",
	}
	for name, rec := range map[string]*httptest.ResponseRecorder{
		"sucesso":     c.get("/session"),
		"erro 4xx":    c.post("/login", `{`),
		"inexistente": c.get("/nao-existe"),
		"sem origem":  c.post("/login", map[string]string{"email": "a@b.com", "password": "x"}, noHeader("Origin")),
	} {
		for h, v := range want {
			if got := rec.Header().Get(h); got != v {
				t.Errorf("%s: %s = %q, quer %q", name, h, got, v)
			}
		}
		if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "frame-ancestors 'none'") {
			t.Errorf("%s: CSP = %q", name, csp)
		}
		if hsts := rec.Header().Get("Strict-Transport-Security"); !strings.Contains(hsts, "max-age=") {
			t.Errorf("%s: HSTS = %q", name, hsts)
		}
	}
}

// --- origem ----------------------------------------------------------------------------------

func TestOriginCheckOnStateChangingRequests(t *testing.T) {
	e := newEnv(t)
	c := e.client(t)
	body := map[string]string{"email": "a@example.com", "password": "x"}

	for name, opt := range map[string]reqOpt{
		"sem Origin":                noHeader("Origin"),
		"Origin de outro site":      withHeader("Origin", "https://evil.example.net"),
		"Origin parecido":           withHeader("Origin", "https://app.alo.test.evil.net"),
		"http em vez de https":      withHeader("Origin", "http://app.alo.test"),
		"Origin null":               withHeader("Origin", "null"),
		"Sec-Fetch-Site cross-site": withHeader("Sec-Fetch-Site", "cross-site"),
	} {
		wantCode(t, c.post("/login", body, opt), http.StatusForbidden, "forbidden_origin")
		_ = name
	}
	// A origem do painel passa (a falha agora é de credenciais, não de origem).
	wantCode(t, c.post("/login", body), http.StatusUnauthorized, "invalid_credentials")
	// Leitura (GET) não exige Origin.
	wantStatus(t, c.get("/session", noHeader("Origin")), http.StatusOK)
}

func TestExtraOriginsAreAllowed(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.ExtraOrigins = []string{"https://admin.alo.test"} })
	c := e.client(t)
	rec := c.post("/login", map[string]string{"email": "a@example.com", "password": "x"}, withHeader("Origin", "https://admin.alo.test"))
	wantCode(t, rec, http.StatusUnauthorized, "invalid_credentials")
}

// --- JSON ---------------------------------------------------------------------------------------

func TestJSONStrictness(t *testing.T) {
	e := newEnv(t)
	c := e.client(t)
	big := `{"email":"a@example.com","password":"` + strings.Repeat("x", 70<<10) + `"}`

	wantCode(t, c.post("/login", `{"email":"a@example.com","password":"x"}`, withHeader("Content-Type", "text/plain")),
		http.StatusUnsupportedMediaType, "unsupported_media_type")
	wantCode(t, c.post("/login", `{"email":"a@example.com","password":"x","admin":true}`),
		http.StatusBadRequest, "invalid_json") // campo desconhecido
	wantCode(t, c.post("/login", `{"email":"a@example.com","password":"x"}{"x":1}`),
		http.StatusBadRequest, "invalid_json") // dois valores
	wantCode(t, c.post("/login", `{"email":`), http.StatusBadRequest, "invalid_json")
	wantCode(t, c.post("/login", `[1,2,3]`), http.StatusBadRequest, "invalid_json")
	wantCode(t, c.post("/login", big), http.StatusRequestEntityTooLarge, "payload_too_large")
	// application/json com charset é aceito.
	wantCode(t, c.post("/login", `{"email":"a@example.com","password":"x"}`, withHeader("Content-Type", "application/json; charset=utf-8")),
		http.StatusUnauthorized, "invalid_credentials")
}

func TestProblemJSONFormat(t *testing.T) {
	e := newEnv(t)
	rec := e.client(t).post("/login", `{`)
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Errorf("Content-Type = %q", ct)
	}
	b := decodeBody(t, rec)
	if b["status"] != float64(400) || b["code"] != "invalid_json" || b["title"] == "" {
		t.Errorf("problem+json: %v", b)
	}
}

func TestUnknownRouteIsJSON404(t *testing.T) {
	e := newEnv(t)
	wantCode(t, e.client(t).get("/nao-existe"), http.StatusNotFound, "not_found")
}

// --- pânico -----------------------------------------------------------------------------------------

func TestPanicIsContainedAndNotLeaked(t *testing.T) {
	e := newEnv(t)
	h := e.srv.recoverer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("segredo-que-nao-pode-vazar")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(ctx, http.MethodPost, "/x", strings.NewReader(`{"password":"minha-senha"}`)))
	wantCode(t, rec, http.StatusInternalServerError, "internal")
	if strings.Contains(rec.Body.String(), "segredo-que-nao-pode-vazar") {
		t.Fatal("a mensagem do panic vazou ao cliente")
	}
	if strings.Contains(e.logs.String(), "minha-senha") {
		t.Fatal("o corpo da requisição foi parar no log")
	}
}

// --- CSRF -----------------------------------------------------------------------------------------------

func TestCSRFRequiredForAuthenticatedStateChanges(t *testing.T) {
	e := newEnv(t)
	u := e.users.add("ana@example.com", goodPW)
	c := e.client(t)
	c.login(u.Email, goodPW)
	good := c.csrf

	c.csrf = ""
	wantCode(t, c.post("/logout", nil), http.StatusForbidden, "csrf_invalid")
	c.csrf = "token-errado"
	wantCode(t, c.post("/logout", nil), http.StatusForbidden, "csrf_invalid")
	// O token de OUTRA sessão não vale nesta.
	other := e.client(t)
	other.login(u.Email, goodPW)
	c.csrf = other.csrf
	wantCode(t, c.post("/logout", nil), http.StatusForbidden, "csrf_invalid")

	// Leituras não exigem CSRF; escritas com o token certo passam.
	c.csrf = ""
	wantStatus(t, c.get("/sessions"), http.StatusOK)
	c.csrf = good
	wantStatus(t, c.post("/logout", nil), http.StatusNoContent)
}

func TestAuthenticatedRoutesNeedASession(t *testing.T) {
	e := newEnv(t)
	c := e.client(t)
	for _, tc := range []struct{ method, path string }{
		{"POST", "/logout"}, {"POST", "/logout-all"}, {"GET", "/sessions"}, {"DELETE", "/sessions/x"},
		{"POST", "/reauth"}, {"POST", "/password/change"}, {"GET", "/mfa"}, {"POST", "/mfa/totp/begin"},
		{"POST", "/mfa/totp/confirm"}, {"DELETE", "/mfa/totp"}, {"POST", "/mfa/recovery-codes"},
		{"POST", "/passkey/register/begin"}, {"POST", "/passkey/register/finish"}, {"GET", "/passkeys"},
		{"DELETE", "/passkeys/abc"}, {"POST", "/oidc/google/link"},
	} {
		rec := c.do(tc.method, "/bff/auth"+tc.path, nil)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s sem sessão = %d, quer 401", tc.method, tc.path, rec.Code)
		}
	}
}
