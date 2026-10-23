package bff

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Americo509/alo-api/internal/identity/passkey"
)

// Depois de uma sequência completa de ações (cadastro, login, falhas, MFA,
// recuperação, troca de senha, passkeys, login federado), nenhum segredo pode
// ter ido parar nos logs nem nos eventos de auditoria (LGPD; ADR-0007 item 9).
func TestNoSecretsInLogsOrAuditTrail(t *testing.T) {
	e := newEnv(t)
	u := e.users.add("ana@example.com", goodPW)
	e.flow.resetTokens["tok-reset-secreto"] = u.ID
	e.flow.verifyTokens["tok-verify-secreto"] = true
	e.flow.registerErr = nil

	anon := e.client(t)
	anon.post("/register", map[string]string{"email": "nova@example.com", "password": "senha-do-cadastro-777"})
	anon.post("/register", map[string]string{"email": "x@example.com", "password": "curta"})
	anon.post("/verify-email", map[string]string{"token": "tok-verify-secreto"})
	anon.post("/login", map[string]string{"email": "ana@example.com", "password": "senha-errada-999"})
	anon.post("/password/forgot", map[string]string{"email": "ana@example.com"})
	anon.post("/password/reset", map[string]string{"token": "tok-reset-secreto", "password": "senha-via-reset-888"})
	e.flow.registerErr = errBoom
	anon.post("/register", map[string]string{"email": "y@example.com", "password": "senha-que-quebra-555"})

	c := e.client(t)
	c.login(u.Email, "senha-via-reset-888")
	e.mfa.enable(u.ID)
	c.post("/mfa/totp/confirm", map[string]string{"code": "000000"})
	c.post("/reauth", map[string]string{"password": "senha-errada-reauth-111"})
	c.post("/password/change", map[string]string{"current_password": "senha-via-reset-888", "new_password": "senha-trocada-666"})
	c.post("/passkey/register/finish?label=meu-notebook", `{"segredo":"x"}`, withHeader("X-Passkey-Ceremony", "cerimonia-secreta"))
	e.pk.loginErr = passkey.ErrCloned
	anon.post("/passkey/login/finish", `{"resposta":"autenticador-secreto"}`, withHeader("X-Passkey-Ceremony", "cerimonia-secreta-2"))
	e.pk.loginErr = nil

	mfaClient := e.client(t)
	mfaClient.post("/login", map[string]string{"email": "ana@example.com", "password": "senha-trocada-666"})
	oc := e.client(t)
	withBinding(oc)
	e.oidc.err = errBoom
	callbackGET(oc, "google", "state=state-secreto&code=codigo-oauth-secreto")

	secrets := []string{
		goodPW, "senha-do-cadastro-777", "senha-errada-999", "senha-via-reset-888", "senha-que-quebra-555",
		"senha-errada-reauth-111", "senha-trocada-666", totpOK, recoveryOK,
		"tok-reset-secreto", "tok-verify-secreto", "cerimonia-secreta", "autenticador-secreto",
		"state-secreto", "codigo-oauth-secreto", "binding-xyz", "captcha-ok",
	}
	// Valores sensíveis gerados em execução: IDs de sessão e tokens CSRF.
	for _, ck := range c.cookies {
		secrets = append(secrets, ck.Value)
	}
	secrets = append(secrets, c.csrf)

	var audit strings.Builder
	for _, ev := range e.aud.All() {
		raw, _ := json.Marshal(ev)
		audit.Write(raw)
		fmt.Fprintf(&audit, "%+v\n", ev)
	}
	haystack := map[string]string{"logs": e.logs.String(), "auditoria": audit.String()}
	for where, text := range haystack {
		for _, s := range secrets {
			if s != "" && strings.Contains(text, s) {
				t.Errorf("segredo %q apareceu em %s", s, where)
			}
		}
	}
	// A auditoria não pode ter o e-mail em claro (identifica o titular por ID).
	if strings.Contains(audit.String(), "@example.com") {
		t.Error("e-mail em claro na auditoria")
	}
	if len(e.aud.All()) == 0 {
		t.Fatal("o cenário não gerou eventos; o teste não provou nada")
	}
}

// Mensagens de erro ao cliente nunca ecoam a entrada nem detalhes internos.
func TestErrorResponsesDoNotEchoInput(t *testing.T) {
	e := newEnv(t)
	c := e.client(t)
	const marker = "MARCADOR-DE-ENTRADA-<script>"
	for _, rec := range []*httptest.ResponseRecorder{
		c.post("/login", map[string]string{"email": marker, "password": marker}),
		c.post("/register", map[string]string{"email": marker, "password": marker}),
		c.post("/verify-email", map[string]string{"token": marker}),
		c.post("/password/reset", map[string]string{"token": marker, "password": marker}),
		c.post("/login/mfa", map[string]string{"mfa_token": marker, "code": marker}),
		c.post("/oidc/"+"google"+"/start", `{"x":"`+marker+`"}`),
	} {
		if strings.Contains(rec.Body.String(), "MARCADOR") {
			t.Errorf("a resposta ecoou a entrada: %s", rec.Body.String())
		}
		if rec.Code < 400 {
			continue
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
			t.Errorf("erro sem problem+json: %s", ct)
		}
	}
}

// --- configuração ----------------------------------------------------------------------------------

func TestNewValidatesConfigAndDeps(t *testing.T) {
	e := newEnv(t)
	good := DefaultConfig(panelOrigin, key32(1), key32(2))
	deps := Deps{
		Flow: e.flow, Sessions: e.sess, Users: e.users, MFA: e.mfa, Passkeys: e.pk, OIDC: e.oidc,
		Guard: e.guard, Counter: e.counter, Ephemeral: e.eph, Audit: e.aud, Clock: e.clk,
	}
	if _, err := New(good, deps); err != nil {
		t.Fatalf("configuração válida recusada: %v", err)
	}
	bad := map[string]func(*Config){
		"chave CSRF curta":    func(c *Config) { c.CSRFKey = key32(1)[:16] },
		"chave de hash curta": func(c *Config) { c.KeyedHashKey = nil },
		"origem em http":      func(c *Config) { c.PublicOrigin = "http://app.exemplo.com.br" },
		"origem com caminho":  func(c *Config) { c.PublicOrigin = "https://app.exemplo.com.br/painel" },
		"origem extra ruim":   func(c *Config) { c.ExtraOrigins = []string{"ftp://x"} },
		"tempo inválido":      func(c *Config) { c.ReauthMaxAge = 0 },
	}
	for name, mutate := range bad {
		cfg := good
		mutate(&cfg)
		if _, err := New(cfg, deps); err == nil {
			t.Errorf("%s: aceito", name)
		}
	}
	if _, err := New(DefaultConfig("http://localhost:5173", key32(1), key32(2)), deps); err != nil {
		t.Errorf("localhost em http deveria valer em desenvolvimento: %v", err)
	}
	broken := deps
	broken.Audit = nil
	if _, err := New(good, broken); err == nil {
		t.Error("dependência ausente aceita")
	}
}

// --- verificador anti-robô ---------------------------------------------------------------------------

func TestSiteVerify(t *testing.T) {
	var gotForm map[string]string
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_ = r.ParseForm()
		gotForm = map[string]string{
			"secret": r.PostForm.Get("secret"), "response": r.PostForm.Get("response"), "remoteip": r.PostForm.Get("remoteip"),
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success": ` + map[bool]string{true: "true", false: "false"}[r.PostForm.Get("response") == "bom"] + `}`))
	}))
	defer srv.Close()

	v, err := NewSiteVerify(srv.URL, "segredo-do-captcha", srv.Client(), true)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Verify(ctx, "bom", "203.0.113.9"); err != nil {
		t.Fatalf("prova válida recusada: %v", err)
	}
	if gotForm["secret"] != "segredo-do-captcha" || gotForm["response"] != "bom" || gotForm["remoteip"] != "203.0.113.9" {
		t.Errorf("formulário enviado: %v", gotForm)
	}
	if err := v.Verify(ctx, "ruim", ""); !errors.Is(err, ErrChallenge) {
		t.Fatalf("prova inválida aceita: %v", err)
	}
	before := calls
	for _, tok := range []string{"", strings.Repeat("x", 3000)} {
		if err := v.Verify(ctx, tok, ""); !errors.Is(err, ErrChallenge) {
			t.Errorf("token %d bytes: %v", len(tok), err)
		}
	}
	if calls != before {
		t.Error("tokens vazios ou enormes não deveriam ir ao provedor")
	}
}

func TestSiteVerifyFailuresAreNotChallengeErrorsAndDoNotLeak(t *testing.T) {
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadGateway) }))
	defer down.Close()
	v, _ := NewSiteVerify(down.URL, "segredo-do-captcha", down.Client(), true)
	err := v.Verify(ctx, "bom", "")
	if err == nil || errors.Is(err, ErrChallenge) {
		t.Fatalf("indisponibilidade deveria ser erro distinto do desafio: %v", err)
	}
	if strings.Contains(err.Error(), "segredo-do-captcha") {
		t.Fatal("o segredo vazou na mensagem de erro")
	}

	garbage := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("não é json")) }))
	defer garbage.Close()
	v2, _ := NewSiteVerify(garbage.URL, "s", garbage.Client(), true)
	if err := v2.Verify(ctx, "bom", ""); err == nil || errors.Is(err, ErrChallenge) {
		t.Fatalf("resposta inválida: %v", err)
	}

	unreachable, _ := NewSiteVerify("http://127.0.0.1:1", "segredo-do-captcha", &http.Client{Timeout: time.Second}, true)
	if err := unreachable.Verify(ctx, "bom", ""); err == nil || strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("erro de rede: %v", err)
	}
}

func TestNewSiteVerifyValidation(t *testing.T) {
	if _, err := NewSiteVerify("http://captcha.example.com/verify", "s", nil, false); err == nil {
		t.Error("http aceito sem permissão")
	}
	if _, err := NewSiteVerify("https://captcha.example.com/verify", "", nil, false); err == nil {
		t.Error("segredo vazio aceito")
	}
	if _, err := NewSiteVerify("https://captcha.example.com/verify", "s", nil, false); err != nil {
		t.Errorf("configuração válida recusada: %v", err)
	}
}
