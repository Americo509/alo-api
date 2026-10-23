package bff

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Americo509/alo-api/internal/audit"
	"github.com/Americo509/alo-api/internal/identity"
	"github.com/Americo509/alo-api/internal/identity/oidclogin"
)

func withBinding(c *client) {
	c.cookies[oidclogin.BindingCookieName] = &http.Cookie{Name: oidclogin.BindingCookieName, Value: "binding-xyz"} //nolint:gosec // G124: cookie do navegador simulado no teste
}

func callbackGET(c *client, provider, query string, opts ...reqOpt) *recorder {
	return c.do(http.MethodGet, "/bff/auth/oidc/"+provider+"/callback?"+query, nil, opts...)
}

// --- início do fluxo ------------------------------------------------------------------------

func TestOIDCStartSetsBindingCookieAndReturnsURL(t *testing.T) {
	e := newEnv(t)
	c := e.client(t)
	rec := c.post("/oidc/google/start", nil)
	wantStatus(t, rec, http.StatusOK)
	if decodeBody(t, rec)["url"] != "https://idp.example/authorize?state=abc" {
		t.Fatalf("corpo: %s", rec.Body.String())
	}
	ck := cookieOf(rec, oidclogin.BindingCookieName)
	if ck == nil || ck.Value != "binding-xyz" {
		t.Fatalf("cookie de binding: %+v", ck)
	}
	if !ck.HttpOnly || !ck.Secure || ck.SameSite != http.SameSiteLaxMode || ck.Path != "/" || ck.Domain != "" {
		t.Errorf("atributos: %+v", ck)
	}
	if e.oidc.begun[0].Provider != "google" || e.oidc.begun[0].Intent != oidclogin.IntentLogin {
		t.Errorf("Begin: %+v", e.oidc.begun)
	}
	// O corpo não carrega o binding (ele só existe no cookie HttpOnly).
	if strings.Contains(rec.Body.String(), "binding-xyz") {
		t.Error("o binding vazou no corpo")
	}
}

func TestOIDCStartForFormPostProviderUsesSameSiteNone(t *testing.T) {
	e := newEnv(t)
	e.oidc.crossSite = true // Apple
	rec := e.client(t).post("/oidc/apple/start", nil)
	wantStatus(t, rec, http.StatusOK)
	if ck := cookieOf(rec, oidclogin.BindingCookieName); ck == nil || ck.SameSite != http.SameSiteNoneMode || !ck.Secure || !ck.HttpOnly {
		t.Fatalf("cookie para form_post: %+v", ck)
	}
}

func TestOIDCStartGuards(t *testing.T) {
	e := newEnv(t)
	c := e.client(t)
	wantCode(t, c.post("/oidc/facebook/start", nil), http.StatusNotFound, "unknown_provider")
	wantCode(t, c.post("/oidc/google/start", nil, noHeader("Origin")), http.StatusForbidden, "forbidden_origin")
}

func TestOIDCLinkNeedsRecentAuthAndPassesTheUser(t *testing.T) {
	e := newEnv(t)
	c, u := loggedIn(t, e, "ana@example.com")
	wantStatus(t, c.post("/oidc/google/link", nil), http.StatusOK)
	got := e.oidc.begun[0]
	if got.Intent != oidclogin.IntentLink || got.Link != u.ID {
		t.Fatalf("Begin(link): %+v", got)
	}
	e.clk.Advance(11 * time.Minute)
	wantCode(t, c.post("/oidc/google/link", nil), http.StatusUnauthorized, "reauth_required")
	wantCode(t, e.client(t).post("/oidc/google/link", nil), http.StatusUnauthorized, "unauthenticated")
}

// --- callback ---------------------------------------------------------------------------------

func TestOIDCCallbackLoginSuccess(t *testing.T) {
	e := newEnv(t)
	u := e.users.add("ana@example.com", "")
	e.oidc.result = oidclogin.Result{User: u, Intent: oidclogin.IntentLogin}
	c := e.client(t)
	withBinding(c)

	// O callback do provedor chega de OUTRO site: não pode ser barrado por Origin.
	rec := callbackGET(c, "google", "state=st1&code=cd1",
		withHeader("Sec-Fetch-Site", "cross-site"), withHeader("Origin", "https://accounts.google.com"))
	wantStatus(t, rec, http.StatusSeeOther)
	if loc := rec.Header().Get("Location"); loc != panelOrigin+"/" {
		t.Fatalf("Location = %q", loc)
	}
	if cookieOf(rec, "__Host-session") == nil {
		t.Fatal("sem sessão")
	}
	// O binding é de uso único: o cookie é apagado.
	if ck := cookieOf(rec, oidclogin.BindingCookieName); ck == nil || ck.MaxAge >= 0 {
		t.Error("cookie de binding não foi apagado")
	}
	in := e.oidc.got[0]
	if in.Provider != "google" || in.State != "st1" || in.Code != "cd1" || in.Binding != "binding-xyz" {
		t.Errorf("CallbackInput = %+v", in)
	}
	sess := decodeBody(t, c.get("/session"))
	amr, _ := sess["amr"].([]any)
	if sess["authenticated"] != true || len(amr) != 1 || amr[0] != "oidc" {
		t.Fatalf("/session = %v", sess)
	}
	if len(e.aud.OfType(audit.OIDCLogin)) != 1 {
		t.Error("login federado não auditado")
	}
	if rec.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Error("o callback deve impedir vazamento do state por Referer")
	}
}

func TestOIDCCallbackWithoutBindingIsPassedAsEmpty(t *testing.T) {
	e := newEnv(t)
	e.oidc.err = oidclogin.ErrState
	c := e.client(t) // sem cookie de binding
	rec := callbackGET(c, "google", "state=st1&code=cd1")
	wantStatus(t, rec, http.StatusSeeOther)
	if e.oidc.got[0].Binding != "" {
		t.Fatalf("binding inventado: %q", e.oidc.got[0].Binding)
	}
	if q := queryOf(t, rec).Query().Get("error"); q != "oidc_state" {
		t.Errorf("error = %q", q)
	}
}

func TestOIDCCallbackErrorMapping(t *testing.T) {
	for err, want := range map[error]string{
		oidclogin.ErrState:           "oidc_state",
		oidclogin.ErrToken:           "oidc_failed",
		oidclogin.ErrAccountExists:   "account_exists",
		oidclogin.ErrEmailUnverified: "email_unverified",
		oidclogin.ErrUserNotAllowed:  "account_unavailable",
		oidclogin.ErrLinkMismatch:    "link_mismatch",
		oidclogin.ErrIdentityTaken:   "identity_taken",
		oidclogin.ErrUnknownProvider: "oidc_failed",
		errBoom:                      "oidc_failed",
	} {
		e := newEnv(t)
		e.oidc.err = err
		c := e.client(t)
		withBinding(c)
		rec := callbackGET(c, "google", "state=s&code=c")
		wantStatus(t, rec, http.StatusSeeOther)
		loc := queryOf(t, rec)
		if got := loc.Query().Get("error"); got != want {
			t.Errorf("%v: error = %q, quer %q", err, got, want)
		}
		if !strings.HasPrefix(rec.Header().Get("Location"), panelOrigin+"/auth/login") {
			t.Errorf("%v: Location = %q", err, rec.Header().Get("Location"))
		}
		if cookieOf(rec, "__Host-session") != nil {
			t.Errorf("%v: criou sessão em caso de erro", err)
		}
		if strings.Contains(rec.Header().Get("Location"), errBoom.Error()) {
			t.Errorf("%v: o texto do erro foi para a URL", err)
		}
	}
}

func TestOIDCCallbackProviderDenied(t *testing.T) {
	e := newEnv(t)
	c := e.client(t)
	withBinding(c)
	rec := callbackGET(c, "google", "error=access_denied&state=s")
	wantStatus(t, rec, http.StatusSeeOther)
	if queryOf(t, rec).Query().Get("error") != "oidc_cancelled" {
		t.Errorf("Location = %q", rec.Header().Get("Location"))
	}
	if len(e.oidc.got) != 0 {
		t.Fatal("o serviço foi chamado apesar de o usuário ter recusado")
	}
	if len(e.aud.OfType(audit.OIDCFailure)) != 1 {
		t.Error("recusa não auditada")
	}
}

func TestOIDCCallbackAccountCreatedIsAudited(t *testing.T) {
	e := newEnv(t)
	u := e.users.add("nova@example.com", "")
	e.oidc.result = oidclogin.Result{User: u, Intent: oidclogin.IntentLogin, Created: true}
	c := e.client(t)
	withBinding(c)
	wantStatus(t, callbackGET(c, "google", "state=s&code=c"), http.StatusSeeOther)
	if len(e.aud.OfType(audit.OIDCAccountCreated)) != 1 {
		t.Error("criação de conta não auditada")
	}
}

func TestOIDCCallbackAsksForSecondFactorWhenEnabled(t *testing.T) {
	e := newEnv(t)
	u := e.users.add("ana@example.com", "")
	e.mfa.enable(u.ID)
	e.oidc.result = oidclogin.Result{User: u, Intent: oidclogin.IntentLogin}
	c := e.client(t)
	withBinding(c)

	rec := callbackGET(c, "google", "state=s&code=c")
	wantStatus(t, rec, http.StatusSeeOther)
	if cookieOf(rec, "__Host-session") != nil {
		t.Fatal("abriu a sessão sem o segundo fator")
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || loc.Path != "/auth/mfa" {
		t.Fatalf("Location = %q", rec.Header().Get("Location"))
	}
	// O token vai no FRAGMENTO (não chega ao servidor nem a logs).
	if loc.RawQuery != "" || !strings.HasPrefix(loc.Fragment, "mfa=") {
		t.Fatalf("o token deveria estar no fragmento: %q", rec.Header().Get("Location"))
	}
	tok := strings.TrimPrefix(loc.Fragment, "mfa=")
	wantStatus(t, c.post("/login/mfa", map[string]string{"mfa_token": tok, "code": totpOK}), http.StatusOK)
	amr, _ := decodeBody(t, c.get("/session"))["amr"].([]any)
	if len(amr) != 2 || amr[0] != "oidc" || amr[1] != "mfa" {
		t.Fatalf("amr = %v", amr)
	}
}

// --- vínculo ----------------------------------------------------------------------------------------

func TestOIDCLinkCallback(t *testing.T) {
	e := newEnv(t)
	c, u := loggedIn(t, e, "ana@example.com")
	e.oidc.result = oidclogin.Result{User: u, Intent: oidclogin.IntentLink, Linked: true}
	withBinding(c)

	rec := callbackGET(c, "google", "state=s&code=c")
	wantStatus(t, rec, http.StatusSeeOther)
	loc := queryOf(t, rec)
	if loc.Path != "/settings/security" || loc.Query().Get("linked") != "google" {
		t.Fatalf("Location = %q", rec.Header().Get("Location"))
	}
	if e.oidc.got[0].SessionUserID != u.ID {
		t.Fatalf("o usuário logado não foi informado: %v", e.oidc.got[0].SessionUserID)
	}
	if len(e.aud.OfType(audit.OIDCLinked)) != 1 {
		t.Error("vínculo não auditado")
	}
}

func TestOIDCLinkErrorReturnsToSecuritySettings(t *testing.T) {
	e := newEnv(t)
	c, _ := loggedIn(t, e, "ana@example.com")
	e.oidc.err = oidclogin.ErrIdentityTaken
	withBinding(c)
	rec := callbackGET(c, "google", "state=s&code=c")
	loc := queryOf(t, rec)
	if loc.Path != "/settings/security" || loc.Query().Get("error") != "identity_taken" {
		t.Fatalf("Location = %q", rec.Header().Get("Location"))
	}
}

// --- Apple: form_post cross-site ---------------------------------------------------------------------

func TestOIDCAppleFormPostIsStashedAndRedirectedSameSite(t *testing.T) {
	e := newEnv(t)
	u := e.users.add("ana@example.com", "")
	e.oidc.result = oidclogin.Result{User: u, Intent: oidclogin.IntentLogin}
	c := e.client(t)
	withBinding(c)

	form := url.Values{"state": {"st-apple"}, "code": {"codigo-secreto-da-apple"}, "user": {`{"name":{"firstName":"Bia"}}`}}
	post := c.do(http.MethodPost, "/bff/auth/oidc/apple/callback", form.Encode(),
		withHeader("Content-Type", "application/x-www-form-urlencoded"),
		withHeader("Origin", "https://appleid.apple.com"), withHeader("Sec-Fetch-Site", "cross-site"))
	wantStatus(t, post, http.StatusSeeOther)
	loc := post.Header().Get("Location")
	if !strings.HasPrefix(loc, panelOrigin+"/bff/auth/oidc/apple/callback?cb=") {
		t.Fatalf("Location = %q", loc)
	}
	// O código e o state NÃO podem ir para a URL (logs, Referer, histórico).
	if strings.Contains(loc, "codigo-secreto-da-apple") || strings.Contains(loc, "st-apple") {
		t.Fatalf("parâmetros sensíveis na URL de redirecionamento: %q", loc)
	}
	if len(e.oidc.got) != 0 {
		t.Fatal("o POST cross-site não deveria concluir o login (o cookie de sessão não vem nele)")
	}

	// Segundo passo: navegação GET no mesmo site.
	path := strings.TrimPrefix(loc, panelOrigin)
	rec := c.do(http.MethodGet, path, nil)
	wantStatus(t, rec, http.StatusSeeOther)
	if rec.Header().Get("Location") != panelOrigin+"/" {
		t.Fatalf("Location final = %q", rec.Header().Get("Location"))
	}
	in := e.oidc.got[0]
	if in.State != "st-apple" || in.Code != "codigo-secreto-da-apple" || in.AppleUser == "" || in.Binding != "binding-xyz" {
		t.Fatalf("CallbackInput = %+v", in)
	}
	// O token é de uso único.
	again := c.do(http.MethodGet, path, nil)
	if queryOf(t, again).Query().Get("error") != "oidc_state" {
		t.Fatalf("replay do token aceito: %q", again.Header().Get("Location"))
	}
	if len(e.oidc.got) != 1 {
		t.Fatal("o replay chegou ao serviço")
	}
}

func TestOIDCCallbackBadStashToken(t *testing.T) {
	e := newEnv(t)
	c := e.client(t)
	for _, cb := range []string{"lixo", "", "AAAA"} {
		rec := c.do(http.MethodGet, "/bff/auth/oidc/apple/callback?cb="+cb+"&state=x&code=y", nil)
		wantStatus(t, rec, http.StatusSeeOther)
	}
	rec := c.do(http.MethodGet, "/bff/auth/oidc/apple/callback?cb=lixo", nil)
	if queryOf(t, rec).Query().Get("error") != "oidc_state" {
		t.Errorf("Location = %q", rec.Header().Get("Location"))
	}
}

// Nenhum redirecionamento aponta para fora do painel (sem open redirect).
func TestOIDCRedirectsStayOnThePanel(t *testing.T) {
	e := newEnv(t)
	u := e.users.add("ana@example.com", "")
	for _, err := range []error{nil, oidclogin.ErrState, oidclogin.ErrAccountExists, errBoom} {
		e.oidc.err = err
		e.oidc.result = oidclogin.Result{User: u, Intent: oidclogin.IntentLogin}
		c := e.client(t)
		withBinding(c)
		rec := callbackGET(c, "google", "state=https://evil.example.net&code=//evil.example.net")
		if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, panelOrigin+"/") {
			t.Errorf("redirecionamento para fora do painel: %q", loc)
		}
	}
	_ = identity.User{}
}
