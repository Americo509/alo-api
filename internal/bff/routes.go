package bff

import (
	"net/http"
)

const prefix = "/bff/auth"

// Handler monta o roteador com as proteções de todas as rotas.
//
//   - público: só confere a origem (requisições que alteram estado);
//   - authed: sessão válida + origem + CSRF;
//   - fresh: authed + autenticação forte recente (ações sensíveis).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	h := func(pattern string, fn http.HandlerFunc) { mux.HandleFunc(pattern, fn) }

	// Estado da sessão (o SPA chama ao carregar). Leitura: sem checagem de origem.
	h("GET "+prefix+"/session", s.handleSession)

	// Cadastro, verificação, login e recuperação.
	h("POST "+prefix+"/register", s.public(s.handleRegister))
	h("POST "+prefix+"/verify-email", s.public(s.handleVerifyEmail))
	h("POST "+prefix+"/login", s.public(s.handleLogin))
	h("POST "+prefix+"/login/mfa", s.public(s.handleLoginMFA))
	h("POST "+prefix+"/password/forgot", s.public(s.handleForgot))
	h("POST "+prefix+"/password/reset", s.public(s.handleReset))

	// Sessões, reautenticação e senha.
	h("POST "+prefix+"/logout", s.authed(s.handleLogout))
	h("POST "+prefix+"/logout-all", s.authed(s.handleLogoutAll))
	h("GET "+prefix+"/sessions", s.authed(s.handleSessionsList))
	h("DELETE "+prefix+"/sessions/{handle}", s.authed(s.handleSessionRevoke))
	h("POST "+prefix+"/reauth", s.authed(s.handleReauth))
	h("POST "+prefix+"/password/change", s.fresh(s.handlePasswordChange))

	// Segundo fator por app autenticador.
	h("GET "+prefix+"/mfa", s.authed(s.handleMFAStatus))
	h("POST "+prefix+"/mfa/totp/begin", s.fresh(s.handleTOTPBegin))
	h("POST "+prefix+"/mfa/totp/confirm", s.authed(s.handleTOTPConfirm))
	h("DELETE "+prefix+"/mfa/totp", s.fresh(s.handleTOTPDisable))
	h("POST "+prefix+"/mfa/recovery-codes", s.fresh(s.handleRecoveryCodes))

	// Passkeys.
	h("POST "+prefix+"/passkey/login/begin", s.public(s.handlePasskeyLoginBegin))
	h("POST "+prefix+"/passkey/login/finish", s.public(s.handlePasskeyLoginFinish))
	h("POST "+prefix+"/passkey/register/begin", s.fresh(s.handlePasskeyRegisterBegin))
	h("POST "+prefix+"/passkey/register/finish", s.authed(s.handlePasskeyRegisterFinish))
	h("GET "+prefix+"/passkeys", s.authed(s.handlePasskeysList))
	h("DELETE "+prefix+"/passkeys/{id}", s.fresh(s.handlePasskeyRemove))

	// Login federado. O callback NÃO passa por public(): a Apple chega por POST
	// de outro site; a proteção dele é state de uso único + cookie de binding.
	h("POST "+prefix+"/oidc/{provider}/start", s.public(s.handleOIDCStart))
	h("POST "+prefix+"/oidc/{provider}/link", s.fresh(s.handleOIDCLink))
	h("GET "+prefix+"/oidc/{provider}/callback", s.handleOIDCCallback)
	h("POST "+prefix+"/oidc/{provider}/callback", s.handleOIDCCallback)

	h("/", func(w http.ResponseWriter, _ *http.Request) { s.problem(w, http.StatusNotFound, "not_found") })

	return s.recoverer(securityHeaders(limitBody(mux)))
}
