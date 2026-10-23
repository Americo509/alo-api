package bff

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Americo509/alo-api/internal/audit"
	"github.com/Americo509/alo-api/internal/identity"
)

// async roda fn numa goroutine e devolve um canal que fecha quando termina.
func async(fn func()) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	return done
}

func isDone(c <-chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}

func waitDone(t *testing.T, c <-chan struct{}) {
	t.Helper()
	select {
	case <-c:
	case <-time.After(5 * time.Second):
		t.Fatal("a requisição não terminou")
	}
}

// --- cadastro ----------------------------------------------------------------------------------

func TestRegisterAlwaysLooksTheSame(t *testing.T) {
	e := newEnv(t)
	c := e.client(t)
	a := c.post("/register", map[string]string{"email": "novo@example.com", "password": goodPW})
	b := c.post("/register", map[string]string{"email": "outro@example.com", "password": goodPW})
	wantStatus(t, a, http.StatusAccepted)
	wantStatus(t, b, http.StatusAccepted)
	if a.Body.String() != b.Body.String() {
		t.Fatalf("respostas diferentes: %q x %q", a.Body.String(), b.Body.String())
	}
	if len(e.flow.registerCalls) != 2 {
		t.Fatalf("flow.Register chamado %d vezes", len(e.flow.registerCalls))
	}
	if len(e.aud.OfType(audit.Registered)) != 2 {
		t.Fatal("cadastro não foi auditado")
	}
}

func TestRegisterValidationErrors(t *testing.T) {
	e := newEnv(t)
	c := e.client(t)
	wantCode(t, c.post("/register", map[string]string{"email": "x@example.com", "password": "curta"}), http.StatusUnprocessableEntity, "password_too_short")
	wantCode(t, c.post("/register", map[string]string{"email": "isto-nao-e-email", "password": goodPW}), http.StatusUnprocessableEntity, "invalid_email")
	e.flow.registerErr = errBoom
	rec := c.post("/register", map[string]string{"email": "x@example.com", "password": goodPW})
	wantCode(t, rec, http.StatusInternalServerError, "internal")
	if strings.Contains(rec.Body.String(), errBoom.Error()) {
		t.Fatal("o texto do erro interno vazou ao cliente")
	}
}

func TestRegisterRateLimits(t *testing.T) {
	e := newEnv(t, func(c *Config) {
		c.Limits.RegisterIP = Rule{Max: 3, Window: time.Hour}
		c.Limits.RegisterEmail = Rule{Max: 1, Window: time.Hour}
	})
	c := e.client(t)
	// Por e-mail: a segunda tentativa para o MESMO destino responde igual, mas não processa.
	for range 2 {
		wantStatus(t, c.post("/register", map[string]string{"email": "alvo@example.com", "password": goodPW}), http.StatusAccepted)
	}
	if n := len(e.flow.registerCalls); n != 1 {
		t.Fatalf("o limite por e-mail não impediu o reenvio: %d chamadas", n)
	}
	// Por IP: a quarta requisição do mesmo IP é recusada, com Retry-After.
	wantStatus(t, c.post("/register", map[string]string{"email": "b@example.com", "password": goodPW}), http.StatusAccepted)
	rec := c.post("/register", map[string]string{"email": "c@example.com", "password": goodPW})
	wantCode(t, rec, http.StatusTooManyRequests, "too_many_requests")
	if ra, _ := strconv.Atoi(rec.Header().Get("Retry-After")); ra <= 0 {
		t.Errorf("Retry-After = %q", rec.Header().Get("Retry-After"))
	}
	// Outro IP não é afetado.
	c.remote = "198.51.100.5:1234"
	wantStatus(t, c.post("/register", map[string]string{"email": "d@example.com", "password": goodPW}), http.StatusAccepted)
}

// O tempo mínimo de resposta impede distinguir "existe" de "não existe" pela latência.
func TestRegisterAndForgotHaveAResponseFloor(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.ResponseFloor = 400 * time.Millisecond })
	for name, call := range map[string]func() *httptest.ResponseRecorder{
		"register": func() *httptest.ResponseRecorder {
			return e.client(t).post("/register", map[string]string{"email": "x@example.com", "password": goodPW})
		},
		"forgot": func() *httptest.ResponseRecorder {
			return e.client(t).post("/password/forgot", map[string]string{"email": "x@example.com"})
		},
	} {
		var rec *httptest.ResponseRecorder
		done := async(func() { rec = call() })
		wctx, cancel := contextWithTimeout()
		if err := e.clk.BlockUntilWaiters(wctx, 1); err != nil {
			cancel()
			t.Fatalf("%s: não esperou o tempo mínimo: %v", name, err)
		}
		cancel()
		if isDone(done) {
			t.Fatalf("%s: respondeu antes do tempo mínimo", name)
		}
		e.clk.Advance(400 * time.Millisecond)
		waitDone(t, done)
		wantStatus(t, rec, http.StatusAccepted)
	}
}

func TestVerifyEmail(t *testing.T) {
	e := newEnv(t)
	c := e.client(t)
	e.flow.verifyTokens["tok-valido"] = true
	wantStatus(t, c.post("/verify-email", map[string]string{"token": "tok-valido"}), http.StatusNoContent)
	wantCode(t, c.post("/verify-email", map[string]string{"token": "tok-valido"}), http.StatusBadRequest, "invalid_token") // uso único
	wantCode(t, c.post("/verify-email", map[string]string{"token": ""}), http.StatusBadRequest, "invalid_token")
	if len(e.aud.OfType(audit.EmailVerified)) != 1 {
		t.Fatal("verificação não auditada")
	}
}

// --- login --------------------------------------------------------------------------------------

// attempt faz um login mandando sempre a prova anti-robô válida: depois de 5
// falhas o servidor passa a exigi-la, e quem não a resolve nem chega a ser
// contado (rejeição barata). Estes testes simulam quem resolve CAPTCHAs.
func attempt(c *client, email, pw string) *httptest.ResponseRecorder {
	return c.post("/login", map[string]string{"email": email, "password": pw, "challenge_token": "captcha-ok"})
}

func TestLoginSuccessSetsSecureSessionCookie(t *testing.T) {
	e := newEnv(t)
	u := e.users.add("ana@example.com", goodPW)
	c := e.client(t)

	rec := c.post("/login", map[string]string{"email": "  ANA@Example.com ", "password": goodPW})
	wantStatus(t, rec, http.StatusOK)
	body := decodeBody(t, rec)
	if body["authenticated"] != true || body["csrf_token"] == "" || body["user"].(map[string]any)["email"] != u.Email {
		t.Fatalf("corpo: %v", body)
	}
	ck := cookieOf(rec, "__Host-session")
	if ck == nil {
		t.Fatal("sem cookie de sessão")
	}
	if !ck.HttpOnly || !ck.Secure || ck.SameSite != http.SameSiteLaxMode || ck.Path != "/" || ck.Domain != "" {
		t.Errorf("atributos do cookie: %+v", ck)
	}
	// O corpo nunca devolve o ID da sessão (só o cookie HttpOnly o carrega).
	if strings.Contains(rec.Body.String(), ck.Value) {
		t.Error("o ID da sessão vazou no corpo")
	}
	// O estado da sessão confere com o login.
	sess := decodeBody(t, c.get("/session"))
	if sess["authenticated"] != true || sess["csrf_token"] != body["csrf_token"] {
		t.Fatalf("/session = %v", sess)
	}
	if len(e.aud.OfType(audit.LoginSuccess)) != 1 {
		t.Fatal("login não auditado")
	}
}

func TestLoginFailuresAreIndistinguishable(t *testing.T) {
	e := newEnv(t)
	e.users.add("ana@example.com", goodPW)
	sus := e.users.add("sus@example.com", goodPW)
	e.users.setStatus(sus.ID, identity.StatusSuspended)

	var bodies []string
	for name, in := range map[string]map[string]string{
		"senha errada":   {"email": "ana@example.com", "password": "errada-errada-123"},
		"sem usuário":    {"email": "fantasma@example.com", "password": goodPW},
		"conta suspensa": {"email": "sus@example.com", "password": goodPW},
		"e-mail lixo":    {"email": "lixo", "password": goodPW},
	} {
		rec := e.client(t).post("/login", in)
		wantCode(t, rec, http.StatusUnauthorized, "invalid_credentials")
		bodies = append(bodies, rec.Body.String())
		if cookieOf(rec, "__Host-session") != nil {
			t.Errorf("%s: criou sessão", name)
		}
	}
	for _, b := range bodies[1:] {
		if b != bodies[0] {
			t.Fatalf("respostas diferentes denunciam o motivo: %q x %q", b, bodies[0])
		}
	}
	for _, ev := range e.aud.OfType(audit.LoginFailure) {
		if ev.UserID.String() != "00000000-0000-0000-0000-000000000000" {
			t.Errorf("a falha de login foi atribuída a um usuário: %v", ev.UserID)
		}
	}
}

func TestLoginTriggersRehash(t *testing.T) {
	e := newEnv(t)
	u := e.users.add("ana@example.com", goodPW)
	e.flow.needsRehash = true
	newEnvLogin(e, t, u.Email)
	if len(e.flow.rehashCalls) != 1 || e.flow.rehashCalls[0] != u.ID {
		t.Fatalf("rehash não foi pedido: %v", e.flow.rehashCalls)
	}
}

func newEnvLogin(e *env, t *testing.T, email string) *client {
	c := e.client(t)
	c.login(email, goodPW)
	return c
}

func TestLoginProgressiveDelay(t *testing.T) {
	g := noDelayGuard()
	g.DelayStep, g.MaxDelay = 500*time.Millisecond, 5*time.Second
	e := buildEnv(t, g)
	e.users.add("ana@example.com", goodPW)
	c := e.client(t)
	bad := map[string]string{"email": "ana@example.com", "password": "errada-errada-123"}
	for range 3 { // as 3 primeiras falhas ainda não pagam atraso
		wantCode(t, c.post("/login", bad), http.StatusUnauthorized, "invalid_credentials")
	}
	var rec *httptest.ResponseRecorder
	done := async(func() { rec = c.post("/login", bad) })
	wctx, cancel := contextWithTimeout()
	defer cancel()
	if err := e.clk.BlockUntilWaiters(wctx, 1); err != nil {
		t.Fatalf("a 4ª tentativa não esperou o atraso: %v", err)
	}
	if isDone(done) {
		t.Fatal("respondeu sem esperar o atraso")
	}
	e.clk.Advance(500 * time.Millisecond)
	waitDone(t, done)
	wantCode(t, rec, http.StatusUnauthorized, "invalid_credentials")
}

func TestLoginRequiresChallengeAfterRepeatedFailures(t *testing.T) {
	e := newEnv(t)
	e.users.add("ana@example.com", goodPW)
	c := e.client(t)
	bad := map[string]string{"email": "ana@example.com", "password": "errada-errada-123"}
	for range 5 {
		wantCode(t, c.post("/login", bad), http.StatusUnauthorized, "invalid_credentials")
	}
	good := map[string]string{"email": "ana@example.com", "password": goodPW}
	// Sem a prova anti-robô, nem a senha certa entra.
	wantCode(t, c.post("/login", good), http.StatusPreconditionRequired, "challenge_required")
	good["challenge_token"] = "token-falso"
	wantCode(t, c.post("/login", good), http.StatusPreconditionRequired, "challenge_required")
	good["challenge_token"] = "captcha-ok"
	wantStatus(t, c.post("/login", good), http.StatusOK)
}

func TestChallengeServiceOutageIsNotABypass(t *testing.T) {
	e := newEnv(t)
	e.users.add("ana@example.com", goodPW)
	c := e.client(t)
	for range 5 {
		c.post("/login", map[string]string{"email": "ana@example.com", "password": "errada-errada-123"})
	}
	e.chal.err = errBoom // o verificador caiu
	rec := c.post("/login", map[string]string{"email": "ana@example.com", "password": goodPW, "challenge_token": "captcha-ok"})
	wantCode(t, rec, http.StatusServiceUnavailable, "service_unavailable")
}

func TestLoginBlocksIPAfterManyFailuresWithoutLockingTheAccount(t *testing.T) {
	e := newEnv(t)
	e.users.add("ana@example.com", goodPW)
	attacker := e.client(t)
	for i := range 10 { // BlockAfterIP = 10
		attempt(attacker, "alvo"+strconv.Itoa(i)+"@example.com", "x")
	}
	rec := attempt(attacker, "ana@example.com", goodPW)
	wantCode(t, rec, http.StatusTooManyRequests, "too_many_requests")
	if rec.Header().Get("Retry-After") == "" {
		t.Error("sem Retry-After")
	}
	if len(e.aud.OfType(audit.LoginBlocked)) != 1 {
		t.Error("bloqueio não auditado")
	}
	// A dona da conta, de outro IP, entra normalmente: sem lockout de conta.
	owner := e.client(t)
	owner.remote = "198.51.100.77:4000"
	wantStatus(t, attempt(owner, "ana@example.com", goodPW), http.StatusOK)
}

// Um login válido não pode zerar o limite do IP: senão quem tem conta própria
// alternaria logins válidos para continuar adivinhando senhas de outras contas.
func TestSuccessfulLoginDoesNotResetTheIPLimit(t *testing.T) {
	e := newEnv(t)
	e.users.add("minha@example.com", goodPW)
	c := e.client(t)
	for i := range 9 {
		attempt(c, "vitima"+strconv.Itoa(i)+"@example.com", "x")
	}
	wantStatus(t, attempt(c, "minha@example.com", goodPW), http.StatusOK)
	attempt(c, "vitima9@example.com", "x") // 10ª falha
	wantCode(t, attempt(c, "minha@example.com", goodPW), http.StatusTooManyRequests, "too_many_requests")
}

func TestIPv6AttackerCannotRotateWithinTheSame64(t *testing.T) {
	e := newEnv(t)
	c := e.client(t)
	for i := range 10 {
		c.remote = "[2001:db8:1:2:" + strconv.Itoa(i+1) + "::1]:5000" // 10 endereços do mesmo /64
		attempt(c, "x"+strconv.Itoa(i)+"@example.com", "x")
	}
	c.remote = "[2001:db8:1:2:ffff::9]:5000"
	wantCode(t, attempt(c, "y@example.com", "x"), http.StatusTooManyRequests, "too_many_requests")
}

// --- segundo fator no login -----------------------------------------------------------------

func mfaUser(e *env, email string) identity.User {
	u := e.users.add(email, goodPW)
	e.mfa.enable(u.ID)
	return u
}

func startMFALogin(t *testing.T, e *env, email string) (*client, string) {
	t.Helper()
	c := e.client(t)
	rec := c.post("/login", map[string]string{"email": email, "password": goodPW})
	wantStatus(t, rec, http.StatusOK)
	b := decodeBody(t, rec)
	if b["mfa_required"] != true {
		t.Fatalf("esperava mfa_required: %v", b)
	}
	if cookieOf(rec, "__Host-session") != nil {
		t.Fatal("criou sessão antes do segundo fator")
	}
	if sess := decodeBody(t, c.get("/session")); sess["authenticated"] != false {
		t.Fatalf("autenticado antes do segundo fator: %v", sess)
	}
	return c, b["mfa_token"].(string)
}

func TestMFALoginWithTOTP(t *testing.T) {
	e := newEnv(t)
	mfaUser(e, "ana@example.com")
	c, tok := startMFALogin(t, e, "ana@example.com")

	rec := c.post("/login/mfa", map[string]string{"mfa_token": tok, "code": totpOK})
	wantStatus(t, rec, http.StatusOK)
	if cookieOf(rec, "__Host-session") == nil {
		t.Fatal("sem sessão após o segundo fator")
	}
	sess := decodeBody(t, c.get("/session"))
	amr, _ := sess["amr"].([]any)
	if sess["authenticated"] != true || len(amr) != 2 || amr[0] != "pwd" || amr[1] != "mfa" {
		t.Fatalf("/session = %v", sess)
	}
	if len(e.aud.OfType(audit.MFASuccess)) != 1 || len(e.aud.OfType(audit.LoginSuccess)) != 1 {
		t.Error("eventos de auditoria ausentes")
	}
	// O token é de uso único.
	wantCode(t, c.post("/login/mfa", map[string]string{"mfa_token": tok, "code": totpOK}), http.StatusUnauthorized, "mfa_expired")
}

func TestMFALoginWrongCodeThenLockout(t *testing.T) {
	e := newEnv(t)
	mfaUser(e, "ana@example.com")
	c, tok := startMFALogin(t, e, "ana@example.com")
	for range 5 { // maxMFAAttempts
		wantCode(t, c.post("/login/mfa", map[string]string{"mfa_token": tok, "code": "000000"}), http.StatusUnauthorized, "invalid_code")
	}
	// Esgotadas as tentativas, nem o código certo vale: precisa refazer o login.
	wantCode(t, c.post("/login/mfa", map[string]string{"mfa_token": tok, "code": totpOK}), http.StatusUnauthorized, "mfa_expired")
	if len(e.aud.OfType(audit.MFAFailure)) != 5 {
		t.Errorf("falhas auditadas: %d", len(e.aud.OfType(audit.MFAFailure)))
	}
}

func TestMFAWrongCodeKeepsTheLoginAlive(t *testing.T) {
	e := newEnv(t)
	mfaUser(e, "ana@example.com")
	c, tok := startMFALogin(t, e, "ana@example.com")
	wantCode(t, c.post("/login/mfa", map[string]string{"mfa_token": tok, "code": "000000"}), http.StatusUnauthorized, "invalid_code")
	wantStatus(t, c.post("/login/mfa", map[string]string{"mfa_token": tok, "code": totpOK}), http.StatusOK)
}

func TestMFAMalformedRequestDoesNotBurnTheLogin(t *testing.T) {
	e := newEnv(t)
	mfaUser(e, "ana@example.com")
	c, tok := startMFALogin(t, e, "ana@example.com")
	wantCode(t, c.post("/login/mfa", map[string]string{"mfa_token": tok}), http.StatusBadRequest, "invalid_request")
	wantStatus(t, c.post("/login/mfa", map[string]string{"mfa_token": tok, "code": totpOK}), http.StatusOK)
}

func TestMFARecoveryCode(t *testing.T) {
	e := newEnv(t)
	mfaUser(e, "ana@example.com")
	c, tok := startMFALogin(t, e, "ana@example.com")
	wantStatus(t, c.post("/login/mfa", map[string]string{"mfa_token": tok, "recovery_code": recoveryOK}), http.StatusOK)
	amr, _ := decodeBody(t, c.get("/session"))["amr"].([]any)
	if len(amr) != 3 || amr[2] != "recovery" {
		t.Fatalf("amr = %v", amr)
	}
	if len(e.aud.OfType(audit.RecoveryCodeUsed)) != 1 {
		t.Error("uso do código de recuperação não auditado")
	}
	// O mesmo código não serve de novo.
	c2, tok2 := startMFALogin(t, e, "ana@example.com")
	wantCode(t, c2.post("/login/mfa", map[string]string{"mfa_token": tok2, "recovery_code": recoveryOK}), http.StatusUnauthorized, "invalid_code")
}

func TestMFAPendingExpiresAndGarbageIsRejected(t *testing.T) {
	e := newEnv(t)
	mfaUser(e, "ana@example.com")
	c, tok := startMFALogin(t, e, "ana@example.com")
	e.clk.Advance(6 * time.Minute) // MFAPendingTTL = 5 min
	wantCode(t, c.post("/login/mfa", map[string]string{"mfa_token": tok, "code": totpOK}), http.StatusUnauthorized, "mfa_expired")
	for _, bad := range []string{"", "lixo", "!!!"} {
		wantCode(t, c.post("/login/mfa", map[string]string{"mfa_token": bad, "code": totpOK}), http.StatusUnauthorized, "mfa_expired")
	}
}

func TestMFASuspendedBetweenSteps(t *testing.T) {
	e := newEnv(t)
	u := mfaUser(e, "ana@example.com")
	c, tok := startMFALogin(t, e, "ana@example.com")
	e.users.setStatus(u.ID, identity.StatusSuspended)
	wantCode(t, c.post("/login/mfa", map[string]string{"mfa_token": tok, "code": totpOK}), http.StatusForbidden, "account_unavailable")
}

// --- recuperação de senha --------------------------------------------------------------------

func TestForgotAlwaysLooksTheSame(t *testing.T) {
	e := newEnv(t)
	e.users.add("ana@example.com", goodPW)
	c := e.client(t)
	var bodies []string
	for _, em := range []string{"ana@example.com", "fantasma@example.com", "lixo", ""} {
		rec := c.post("/password/forgot", map[string]string{"email": em})
		wantStatus(t, rec, http.StatusAccepted)
		bodies = append(bodies, rec.Body.String())
	}
	for _, b := range bodies[1:] {
		if b != bodies[0] {
			t.Fatalf("respostas diferentes: %q x %q", b, bodies[0])
		}
	}
	// E-mail malformado nem chega ao fluxo.
	for _, em := range e.flow.recoveryCalls {
		if em == "lixo" || em == "" {
			t.Errorf("e-mail inválido foi processado: %q", em)
		}
	}
}

func TestForgotPerEmailLimitSilentlySkips(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.Limits.ForgotEmail = Rule{Max: 2, Window: time.Hour} })
	c := e.client(t)
	for range 5 {
		wantStatus(t, c.post("/password/forgot", map[string]string{"email": "vitima@example.com"}), http.StatusAccepted)
	}
	if len(e.flow.recoveryCalls) != 2 {
		t.Fatalf("a caixa da vítima receberia %d e-mails; o limite é 2", len(e.flow.recoveryCalls))
	}
}

func TestResetPasswordRevokesAllSessions(t *testing.T) {
	e := newEnv(t)
	u := e.users.add("ana@example.com", goodPW)
	laptop, phone := e.client(t), e.client(t)
	laptop.login(u.Email, goodPW)
	phone.login(u.Email, goodPW)
	e.flow.resetTokens["tok-reset"] = u.ID

	anon := e.client(t)
	wantCode(t, anon.post("/password/reset", map[string]string{"token": "lixo", "password": newPW}), http.StatusBadRequest, "invalid_token")
	// Senha fraca: erro de validação, token continua valendo.
	wantCode(t, anon.post("/password/reset", map[string]string{"token": "tok-reset", "password": "curta"}), http.StatusUnprocessableEntity, "password_too_short")
	wantStatus(t, anon.post("/password/reset", map[string]string{"token": "tok-reset", "password": newPW}), http.StatusNoContent)

	for name, c := range map[string]*client{"notebook": laptop, "celular": phone} {
		if decodeBody(t, c.get("/session"))["authenticated"] != false {
			t.Errorf("a sessão do %s sobreviveu à recuperação de senha", name)
		}
	}
	wantCode(t, anon.post("/password/reset", map[string]string{"token": "tok-reset", "password": newPW}), http.StatusBadRequest, "invalid_token")
	if len(e.aud.OfType(audit.PasswordResetCompleted)) != 1 {
		t.Error("recuperação não auditada")
	}
}

// --- sessão -------------------------------------------------------------------------------------

func TestSessionEndpointWithoutOrWithBrokenCookie(t *testing.T) {
	e := newEnv(t)
	c := e.client(t)
	rec := c.get("/session")
	wantStatus(t, rec, http.StatusOK)
	if b := decodeBody(t, rec); b["authenticated"] != false || b["csrf_token"] != nil || b["user"] != nil {
		t.Fatalf("anônimo recebeu dados: %v", b)
	}
	// Cookie inválido é limpo.
	c.cookies["__Host-session"] = &http.Cookie{Name: "__Host-session", Value: "lixo"} //nolint:gosec // G124: cookie do navegador simulado no teste
	rec = c.get("/session")
	wantStatus(t, rec, http.StatusOK)
	if ck := cookieOf(rec, "__Host-session"); ck == nil || ck.MaxAge >= 0 {
		t.Error("cookie inválido não foi apagado")
	}
}

func TestLogoutRevokesServerSide(t *testing.T) {
	e := newEnv(t)
	u := e.users.add("ana@example.com", goodPW)
	c := e.client(t)
	c.login(u.Email, goodPW)
	stolen := *c.cookies["__Host-session"] // cópia do cookie antes de sair

	rec := c.post("/logout", nil)
	wantStatus(t, rec, http.StatusNoContent)
	if ck := cookieOf(rec, "__Host-session"); ck == nil || ck.MaxAge >= 0 {
		t.Error("cookie não foi apagado")
	}
	// Mesmo quem guardou o cookie não entra mais.
	attacker := e.client(t)
	attacker.cookies["__Host-session"] = &stolen
	if decodeBody(t, attacker.get("/session"))["authenticated"] != false {
		t.Fatal("cookie copiado ainda vale depois do logout")
	}
}

func TestLogoutAll(t *testing.T) {
	e := newEnv(t)
	u := e.users.add("ana@example.com", goodPW)
	a, b := e.client(t), e.client(t)
	a.login(u.Email, goodPW)
	b.login(u.Email, goodPW)
	wantStatus(t, a.post("/logout-all", nil), http.StatusNoContent)
	if decodeBody(t, b.get("/session"))["authenticated"] != false {
		t.Fatal("a outra sessão sobreviveu")
	}
}

func TestSessionsListAndRevoke(t *testing.T) {
	e := newEnv(t)
	u := e.users.add("ana@example.com", goodPW)
	other := e.users.add("bob@example.com", goodPW)
	laptop, phone, bob := e.client(t), e.client(t), e.client(t)
	phone.remote = "198.51.100.20:1"
	laptop.login(u.Email, goodPW)
	phone.login(u.Email, goodPW)
	bob.login(other.Email, goodPW)

	rec := laptop.get("/sessions", withHeader("User-Agent", "Firefox/130"))
	wantStatus(t, rec, http.StatusOK)
	list := decodeBody(t, rec)["sessions"].([]any)
	if len(list) != 2 {
		t.Fatalf("sessões = %d, quer 2 (e nunca as de outro usuário)", len(list))
	}
	var currentCount int
	var phoneHandle string
	for _, it := range list {
		m := it.(map[string]any)
		if m["current"] == true {
			currentCount++
		} else {
			phoneHandle = m["handle"].(string)
		}
	}
	if currentCount != 1 {
		t.Fatalf("sessões marcadas como atual: %d", currentCount)
	}

	// Bob não consegue encerrar a sessão da Ana, mesmo sabendo o handle.
	wantCode(t, bob.del("/sessions/"+phoneHandle), http.StatusNotFound, "not_found")
	wantStatus(t, laptop.del("/sessions/"+phoneHandle), http.StatusNoContent)
	if decodeBody(t, phone.get("/session"))["authenticated"] != false {
		t.Fatal("a sessão encerrada ainda vale")
	}
	wantCode(t, laptop.del("/sessions/"+phoneHandle), http.StatusNotFound, "not_found")
	wantCode(t, laptop.del("/sessions/lixo"), http.StatusNotFound, "not_found")
}

func TestSuspendedUserLosesTheSession(t *testing.T) {
	e := newEnv(t)
	u := e.users.add("ana@example.com", goodPW)
	c := e.client(t)
	c.login(u.Email, goodPW)
	e.users.setStatus(u.ID, identity.StatusSuspended)
	wantCode(t, c.get("/sessions"), http.StatusUnauthorized, "unauthenticated")
}

// --- reautenticação e troca de senha -------------------------------------------------------------

func TestSensitiveActionsNeedRecentAuthentication(t *testing.T) {
	e := newEnv(t)
	u := e.users.add("ana@example.com", goodPW)
	c := e.client(t)
	c.login(u.Email, goodPW)
	// Logo após o login, a autenticação é recente.
	wantStatus(t, c.post("/mfa/totp/begin", nil), http.StatusOK)

	e.clk.Advance(11 * time.Minute) // ReauthMaxAge = 10 min; a sessão (30 min) ainda vale
	wantCode(t, c.post("/mfa/totp/begin", nil), http.StatusUnauthorized, "reauth_required")
	wantCode(t, c.post("/password/change", map[string]string{"current_password": goodPW, "new_password": newPW}), http.StatusUnauthorized, "reauth_required")
	// Atividade comum não renova a autenticação forte.
	wantStatus(t, c.get("/sessions"), http.StatusOK)
	wantCode(t, c.post("/mfa/totp/begin", nil), http.StatusUnauthorized, "reauth_required")

	wantCode(t, c.post("/reauth", map[string]string{"password": "errada-errada-123"}), http.StatusUnauthorized, "invalid_credentials")
	c.reauth(goodPW)
	wantStatus(t, c.post("/mfa/totp/begin", nil), http.StatusOK)
}

func TestReauthWithTOTPAndRecoveryCode(t *testing.T) {
	e := newEnv(t)
	mfaUser(e, "ana@example.com")
	c, tok := startMFALogin(t, e, "ana@example.com")
	wantStatus(t, c.post("/login/mfa", map[string]string{"mfa_token": tok, "code": totpOK}), http.StatusOK)
	c.csrf = decodeBody(t, c.get("/session"))["csrf_token"].(string)

	e.clk.Advance(11 * time.Minute)
	wantCode(t, c.post("/reauth", map[string]string{"code": "000000"}), http.StatusUnauthorized, "invalid_credentials")
	wantStatus(t, c.post("/reauth", map[string]string{"code": totpOK}), http.StatusNoContent)
	e.clk.Advance(11 * time.Minute)
	wantStatus(t, c.post("/reauth", map[string]string{"recovery_code": recoveryOK}), http.StatusNoContent)
	wantCode(t, c.post("/reauth", map[string]string{}), http.StatusBadRequest, "invalid_request")
}

func TestPasswordChange(t *testing.T) {
	e := newEnv(t)
	u := e.users.add("ana@example.com", goodPW)
	laptop, phone := e.client(t), e.client(t)
	laptop.login(u.Email, goodPW)
	phone.login(u.Email, goodPW)
	oldCookie := *laptop.cookies["__Host-session"]

	wantCode(t, laptop.post("/password/change", map[string]string{"current_password": "errada-errada-123", "new_password": newPW}), http.StatusUnauthorized, "invalid_credentials")
	wantCode(t, laptop.post("/password/change", map[string]string{"current_password": goodPW, "new_password": "curta"}), http.StatusUnprocessableEntity, "password_too_short")

	rec := laptop.post("/password/change", map[string]string{"current_password": goodPW, "new_password": newPW})
	wantStatus(t, rec, http.StatusOK)
	newToken := decodeBody(t, rec)["csrf_token"].(string)
	laptop.csrf = newToken

	// O ID da sessão mudou (anti-fixação) e o antigo morreu.
	if cookieOf(rec, "__Host-session") == nil || cookieOf(rec, "__Host-session").Value == oldCookie.Value {
		t.Fatal("o ID da sessão não foi trocado")
	}
	ghost := e.client(t)
	ghost.cookies["__Host-session"] = &oldCookie
	if decodeBody(t, ghost.get("/session"))["authenticated"] != false {
		t.Fatal("o ID antigo da sessão ainda vale")
	}
	// A sessão atual continua; as outras caíram.
	if decodeBody(t, laptop.get("/session"))["authenticated"] != true {
		t.Fatal("a sessão atual caiu")
	}
	if decodeBody(t, phone.get("/session"))["authenticated"] != false {
		t.Fatal("a outra sessão sobreviveu à troca de senha")
	}
	if len(e.aud.OfType(audit.PasswordChanged)) != 1 {
		t.Error("troca de senha não auditada")
	}
	// Só a senha nova entra.
	fresh := e.client(t)
	wantCode(t, fresh.post("/login", map[string]string{"email": u.Email, "password": goodPW}), http.StatusUnauthorized, "invalid_credentials")
	wantStatus(t, fresh.post("/login", map[string]string{"email": u.Email, "password": newPW}), http.StatusOK)
}
