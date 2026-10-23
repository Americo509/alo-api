package bff

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/Americo509/alo-api/internal/audit"
	"github.com/Americo509/alo-api/internal/identity"
	"github.com/Americo509/alo-api/internal/identity/passkey"
)

func loggedIn(t *testing.T, e *env, email string) (*client, identity.User) {
	t.Helper()
	u := e.users.add(email, goodPW)
	c := e.client(t)
	c.login(email, goodPW)
	return c, u
}

// --- inscrição do app autenticador --------------------------------------------------------

func TestTOTPEnrollmentFlow(t *testing.T) {
	e := newEnv(t)
	c, u := loggedIn(t, e, "ana@example.com")

	if decodeBody(t, c.get("/mfa"))["totp_enabled"] != false {
		t.Fatal("deveria começar sem segundo fator")
	}
	rec := c.post("/mfa/totp/begin", nil)
	wantStatus(t, rec, http.StatusOK)
	if uri, _ := decodeBody(t, rec)["otpauth_uri"].(string); !strings.HasPrefix(uri, "otpauth://totp/") {
		t.Fatalf("otpauth_uri = %q", uri)
	}
	wantCode(t, c.post("/mfa/totp/confirm", map[string]string{"code": "000000"}), http.StatusUnauthorized, "invalid_code")

	rec = c.post("/mfa/totp/confirm", map[string]string{"code": totpOK})
	wantStatus(t, rec, http.StatusOK)
	codes, _ := decodeBody(t, rec)["recovery_codes"].([]any)
	if len(codes) != 2 {
		t.Fatalf("códigos de recuperação: %v", codes)
	}
	if len(e.aud.OfType(audit.TOTPEnabled)) != 1 || len(e.aud.OfType(audit.RecoveryCodesCreated)) != 1 {
		t.Error("ativação não auditada")
	}
	if decodeBody(t, c.get("/mfa"))["totp_enabled"] != true {
		t.Fatal("o segundo fator deveria estar ativo")
	}
	// Reinscrever com o fator ativo é conflito.
	wantCode(t, c.post("/mfa/totp/begin", nil), http.StatusConflict, "conflict")

	// A partir daqui o login pede o segundo fator.
	_, tok := startMFALogin(t, e, u.Email)
	if tok == "" {
		t.Fatal("login sem token de MFA")
	}
}

func TestTOTPActionsNeedRecentAuthentication(t *testing.T) {
	e := newEnv(t)
	c, u := loggedIn(t, e, "ana@example.com")
	e.mfa.enable(u.ID)
	e.clk.Advance(11 * time.Minute)
	wantCode(t, c.post("/mfa/totp/begin", nil), http.StatusUnauthorized, "reauth_required")
	wantCode(t, c.del("/mfa/totp"), http.StatusUnauthorized, "reauth_required")
	wantCode(t, c.post("/mfa/recovery-codes", nil), http.StatusUnauthorized, "reauth_required")
	c.reauth(goodPW)
	wantStatus(t, c.post("/mfa/recovery-codes", nil), http.StatusOK)
	wantStatus(t, c.del("/mfa/totp"), http.StatusNoContent)
	if len(e.aud.OfType(audit.TOTPDisabled)) != 1 {
		t.Error("desativação não auditada")
	}
	wantCode(t, c.post("/mfa/recovery-codes", nil), http.StatusConflict, "conflict") // sem fator ativo
}

func TestTOTPConfirmIsThrottled(t *testing.T) {
	e := newEnv(t)
	c, _ := loggedIn(t, e, "ana@example.com")
	wantStatus(t, c.post("/mfa/totp/begin", nil), http.StatusOK)
	// Sem atraso progressivo neste ambiente, o limite por IP é o que corta a
	// adivinhação do código: a 11ª tentativa errada vem bloqueada.
	var last int
	for range 12 {
		last = c.post("/mfa/totp/confirm", map[string]string{"code": "000000"}).Code
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("adivinhar o código de confirmação não foi contido: último status %d", last)
	}
}

// --- passkeys -----------------------------------------------------------------------------------

func TestPasskeyRegistration(t *testing.T) {
	e := newEnv(t)
	c, _ := loggedIn(t, e, "ana@example.com")

	rec := c.post("/passkey/register/begin", nil)
	wantStatus(t, rec, http.StatusOK)
	if b := decodeBody(t, rec); b["ceremony"] != "ceremony-reg" || b["options"] == nil {
		t.Fatalf("begin: %v", b)
	}
	// O apelido é limpo (controle, tamanho) e a cerimônia vem do cabeçalho.
	label := "Meu\r\nnotebook" + strings.Repeat("é", 200)
	rec = c.post("/passkey/register/finish?label="+urlEscape(label), `{"id":"x"}`, withHeader("X-Passkey-Ceremony", "ceremony-reg"))
	wantStatus(t, rec, http.StatusNoContent)
	if e.pk.regToken != "ceremony-reg" {
		t.Errorf("cerimônia não repassada: %q", e.pk.regToken)
	}
	if strings.ContainsAny(e.pk.regLabel, "\r\n") || len([]rune(e.pk.regLabel)) > 100 {
		t.Errorf("apelido não sanitizado: %q", e.pk.regLabel)
	}
	if len(e.aud.OfType(audit.PasskeyAdded)) != 1 {
		t.Error("passkey adicionada não auditada")
	}
}

func urlEscape(s string) string {
	r := strings.NewReplacer("\r", "%0D", "\n", "%0A", " ", "%20")
	return r.Replace(s)
}

func TestPasskeyRegistrationErrors(t *testing.T) {
	e := newEnv(t)
	c, _ := loggedIn(t, e, "ana@example.com")
	hdr := withHeader("X-Passkey-Ceremony", "x")
	for err, want := range map[error]struct {
		status int
		code   string
	}{
		passkey.ErrCeremony:    {http.StatusBadRequest, "passkey_failed"},
		passkey.ErrNotVerified: {http.StatusBadRequest, "passkey_failed"},
		passkey.ErrLimit:       {http.StatusConflict, "conflict"},
		passkey.ErrDuplicate:   {http.StatusConflict, "conflict"},
		errBoom:                {http.StatusInternalServerError, "internal"},
	} {
		e.pk.finishRegErr = err
		rec := c.post("/passkey/register/finish", `{}`, hdr)
		wantCode(t, rec, want.status, want.code)
		if strings.Contains(rec.Body.String(), errBoom.Error()) {
			t.Error("o erro interno vazou ao cliente")
		}
	}
}

func TestPasskeyRegistrationNeedsRecentAuth(t *testing.T) {
	e := newEnv(t)
	c, _ := loggedIn(t, e, "ana@example.com")
	e.clk.Advance(11 * time.Minute)
	wantCode(t, c.post("/passkey/register/begin", nil), http.StatusUnauthorized, "reauth_required")
}

func TestPasskeyLoginSkipsTOTPAndCreatesSession(t *testing.T) {
	e := newEnv(t)
	u := e.users.add("ana@example.com", goodPW)
	e.mfa.enable(u.ID) // tem TOTP, mas a passkey com verificação do usuário já é forte
	e.pk.user = u
	c := e.client(t)

	rec := c.post("/passkey/login/begin", nil)
	wantStatus(t, rec, http.StatusOK)
	if decodeBody(t, rec)["ceremony"] != "ceremony-login" {
		t.Fatalf("begin: %s", rec.Body.String())
	}
	rec = c.post("/passkey/login/finish", `{"id":"x"}`, withHeader("X-Passkey-Ceremony", "ceremony-login"))
	wantStatus(t, rec, http.StatusOK)
	if e.pk.loginToken != "ceremony-login" {
		t.Errorf("cerimônia não repassada: %q", e.pk.loginToken)
	}
	if cookieOf(rec, "__Host-session") == nil {
		t.Fatal("sem sessão")
	}
	sess := decodeBody(t, c.get("/session"))
	amr, _ := sess["amr"].([]any)
	if sess["authenticated"] != true || len(amr) != 2 || amr[0] != "passkey" || amr[1] != "uv" {
		t.Fatalf("/session = %v", sess)
	}
	if len(e.aud.OfType(audit.PasskeyLogin)) != 1 {
		t.Error("login por passkey não auditado")
	}
}

func TestPasskeyLoginFailuresAreGeneric(t *testing.T) {
	e := newEnv(t)
	e.pk.user = e.users.add("ana@example.com", goodPW)
	for err, want := range map[error]struct {
		status int
		code   string
	}{
		passkey.ErrCloned:         {http.StatusUnauthorized, "passkey_failed"},
		passkey.ErrCeremony:       {http.StatusUnauthorized, "passkey_failed"},
		passkey.ErrNotVerified:    {http.StatusUnauthorized, "passkey_failed"},
		passkey.ErrNotFound:       {http.StatusUnauthorized, "passkey_failed"},
		passkey.ErrUserNotAllowed: {http.StatusForbidden, "account_unavailable"},
	} {
		e.pk.loginErr = err
		c := e.client(t)
		rec := c.post("/passkey/login/finish", `{}`, withHeader("X-Passkey-Ceremony", "x"))
		wantCode(t, rec, want.status, want.code)
		if cookieOf(rec, "__Host-session") != nil {
			t.Errorf("%v: criou sessão", err)
		}
	}
	if len(e.aud.OfType(audit.PasskeyCloneSuspected)) != 1 {
		t.Errorf("clone suspeito não auditado: %d", len(e.aud.OfType(audit.PasskeyCloneSuspected)))
	}
}

func TestPasskeyLoginIsOriginProtectedAndRateLimited(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.Limits.PasskeyBeginIP = Rule{Max: 2, Window: time.Minute} })
	c := e.client(t)
	wantCode(t, c.post("/passkey/login/begin", nil, noHeader("Origin")), http.StatusForbidden, "forbidden_origin")
	wantStatus(t, c.post("/passkey/login/begin", nil), http.StatusOK)
	wantStatus(t, c.post("/passkey/login/begin", nil), http.StatusOK) // 2ª contada (a sem Origin não gasta cota)
	wantCode(t, c.post("/passkey/login/begin", nil), http.StatusTooManyRequests, "too_many_requests")
}

func TestPasskeyListAndRemoveOnlyOwn(t *testing.T) {
	e := newEnv(t)
	alice, au := loggedIn(t, e, "alice@example.com")
	bob, bu := loggedIn(t, e, "bob@example.com")
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	e.pk.stored = []passkey.Stored{
		{UserID: au.ID, Label: "notebook", CreatedAt: now, Credential: webauthn.Credential{ID: []byte("cred-alice")}},
		{UserID: bu.ID, Label: "celular", CreatedAt: now, Credential: webauthn.Credential{ID: []byte("cred-bob")}},
	}
	list := decodeBody(t, alice.get("/passkeys"))["passkeys"].([]any)
	if len(list) != 1 || list[0].(map[string]any)["label"] != "notebook" {
		t.Fatalf("lista da Alice: %v", list)
	}
	idAlice := list[0].(map[string]any)["id"].(string)

	wantCode(t, bob.del("/passkeys/"+idAlice), http.StatusNotFound, "not_found") // Bob não remove a da Alice
	wantCode(t, alice.del("/passkeys/%21%21"), http.StatusNotFound, "not_found") // id inválido
	wantStatus(t, alice.del("/passkeys/"+idAlice), http.StatusNoContent)
	if len(decodeBody(t, alice.get("/passkeys"))["passkeys"].([]any)) != 0 {
		t.Fatal("a passkey continua listada")
	}
	if len(e.aud.OfType(audit.PasskeyRemoved)) != 1 {
		t.Error("remoção não auditada")
	}
}
