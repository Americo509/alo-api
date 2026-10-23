package bff

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Americo509/alo-api/internal/audit"
	"github.com/Americo509/alo-api/internal/identity/ephemeral"
	"github.com/Americo509/alo-api/internal/identity/oidclogin"
)

const (
	callbackStash    = "oidc-cb:"
	callbackStashTTL = 2 * time.Minute
)

// handleOIDCStart inicia o login com um provedor. Devolve a URL do provedor (o
// SPA navega até ela) e grava o cookie de binding deste navegador.
func (s *Server) handleOIDCStart(w http.ResponseWriter, r *http.Request) {
	if !s.within(w, r, "oidc-ip", s.cfg.Limits.OIDCStartIP) {
		return
	}
	br, err := s.d.OIDC.Begin(r.Context(), r.PathValue("provider"), oidclogin.IntentLogin, uuid.Nil)
	s.answerBegin(w, br, err)
}

// handleOIDCLink inicia o vínculo de um provedor à conta do usuário logado.
func (s *Server) handleOIDCLink(w http.ResponseWriter, r *http.Request, a *authCtx) {
	br, err := s.d.OIDC.Begin(r.Context(), r.PathValue("provider"), oidclogin.IntentLink, a.User.ID)
	s.answerBegin(w, br, err)
}

func (s *Server) answerBegin(w http.ResponseWriter, br oidclogin.BeginResult, err error) {
	switch {
	case errors.Is(err, oidclogin.ErrUnknownProvider):
		s.problem(w, http.StatusNotFound, "unknown_provider")
	case err != nil:
		s.internal(w, "falha ao iniciar o login federado", err)
	default:
		oidclogin.SetBindingCookie(w, br.Binding, br.CrossSite)
		s.writeJSON(w, http.StatusOK, map[string]string{"url": br.AuthURL})
	}
}

// callbackParams são os parâmetros que o provedor devolve.
type callbackParams struct {
	State string `json:"s"`
	Code  string `json:"c"`
	Error string `json:"e"`
	User  string `json:"u"` // Apple: nome, só no primeiro consentimento
}

// handleOIDCCallback recebe a volta do provedor. NÃO exige Origin do painel (a
// Apple chega por POST de outro site): a proteção é o state de uso único amarrado
// ao cookie de binding. Responde sempre com redirecionamento 303 para o SPA,
// em endereços fixos da configuração (sem redirecionamento aberto).
func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	provider := r.PathValue("provider")

	if r.Method == http.MethodPost {
		// Apple (form_post): o cookie de sessão Lax não acompanha este POST cross-site.
		// Guarda os parâmetros e segue por um GET no mesmo site, onde a sessão aparece.
		if err := r.ParseForm(); err != nil {
			s.redirectErr(w, r, s.cfg.LoginPath, "oidc_failed")
			return
		}
		token, key, err := ephemeral.NewToken(nil)
		if err != nil {
			s.redirectErr(w, r, s.cfg.LoginPath, "oidc_failed")
			return
		}
		raw, _ := json.Marshal(callbackParams{
			State: r.PostForm.Get("state"), Code: r.PostForm.Get("code"),
			Error: r.PostForm.Get("error"), User: r.PostForm.Get("user"),
		})
		if err := s.d.Ephemeral.Put(r.Context(), callbackStash+key, raw, callbackStashTTL); err != nil {
			s.redirectErr(w, r, s.cfg.LoginPath, "oidc_failed")
			return
		}
		http.Redirect(w, r, s.cfg.PublicOrigin+"/bff/auth/oidc/"+url.PathEscape(provider)+"/callback?cb="+url.QueryEscape(token), http.StatusSeeOther)
		return
	}

	var p callbackParams
	if cb := r.URL.Query().Get("cb"); cb != "" {
		key, err := ephemeral.KeyOf(cb)
		if err != nil {
			s.redirectErr(w, r, s.cfg.LoginPath, "oidc_state")
			return
		}
		raw, err := s.d.Ephemeral.Take(r.Context(), callbackStash+key) // uso único
		if err != nil || json.Unmarshal(raw, &p) != nil {
			s.redirectErr(w, r, s.cfg.LoginPath, "oidc_state")
			return
		}
	} else {
		q := r.URL.Query()
		p = callbackParams{State: q.Get("state"), Code: q.Get("code"), Error: q.Get("error")}
	}
	s.finishOIDC(w, r, provider, p)
}

func (s *Server) finishOIDC(w http.ResponseWriter, r *http.Request, provider string, p callbackParams) {
	ctx := r.Context()
	var binding string
	if c, err := r.Cookie(oidclogin.BindingCookieName); err == nil {
		binding = c.Value
	}
	oidclogin.ClearBindingCookie(w, true) // o binding é de uso único

	if p.Error != "" {
		// O usuário recusou no provedor, ou o provedor falhou.
		s.record(r, audit.OIDCFailure, uuid.Nil, map[string]string{"provedor": provider, "motivo": "recusado"})
		s.redirectErr(w, r, s.cfg.LoginPath, "oidc_cancelled")
		return
	}

	var sessionUser uuid.UUID
	if a, err := s.peek(w, r); err == nil && a != nil {
		sessionUser = a.User.ID
	}
	res, err := s.d.OIDC.Callback(ctx, oidclogin.CallbackInput{
		Provider: provider, State: p.State, Code: p.Code, Binding: binding,
		SessionUserID: sessionUser, AppleUser: p.User,
	})
	if err != nil {
		code := oidcErrorCode(err)
		if code == "oidc_failed" {
			s.log.Warn("falha no callback federado", slog.String("provedor", provider), slog.Any("erro", err))
		}
		s.record(r, audit.OIDCFailure, sessionUser, map[string]string{"provedor": provider, "motivo": code})
		s.redirectErr(w, r, s.errPath(res.Intent, sessionUser), code)
		return
	}

	if res.Intent == oidclogin.IntentLink {
		if res.Linked {
			s.record(r, audit.OIDCLinked, res.User.ID, map[string]string{"provedor": provider})
		}
		http.Redirect(w, r, s.cfg.PublicOrigin+s.cfg.SecurityPath+"?linked="+url.QueryEscape(provider), http.StatusSeeOther)
		return
	}
	if res.Created {
		s.record(r, audit.OIDCAccountCreated, res.User.ID, map[string]string{"provedor": provider})
	}
	mfaToken, _, err := s.establish(w, r, res.User, "oidc")
	if err != nil {
		s.log.Error("falha ao abrir a sessão após o login federado", slog.Any("erro", err))
		s.redirectErr(w, r, s.cfg.LoginPath, "oidc_failed")
		return
	}
	if mfaToken != "" {
		// Token no fragmento: não vai ao servidor nem a logs.
		http.Redirect(w, r, s.cfg.PublicOrigin+s.cfg.MFAPath+"#mfa="+url.QueryEscape(mfaToken), http.StatusSeeOther)
		return
	}
	s.record(r, audit.OIDCLogin, res.User.ID, map[string]string{"provedor": provider})
	s.record(r, audit.LoginSuccess, res.User.ID, map[string]string{"via": "oidc:" + provider})
	http.Redirect(w, r, s.cfg.PublicOrigin+s.cfg.AfterLoginPath, http.StatusSeeOther)
}

// errPath escolhe a tela de erro: quem estava vinculando volta às configurações.
func (s *Server) errPath(intent oidclogin.Intent, sessionUser uuid.UUID) string {
	if intent == oidclogin.IntentLink || sessionUser != uuid.Nil {
		return s.cfg.SecurityPath
	}
	return s.cfg.LoginPath
}

func oidcErrorCode(err error) string {
	switch {
	case errors.Is(err, oidclogin.ErrState):
		return "oidc_state"
	case errors.Is(err, oidclogin.ErrAccountExists):
		return "account_exists"
	case errors.Is(err, oidclogin.ErrEmailUnverified):
		return "email_unverified"
	case errors.Is(err, oidclogin.ErrUserNotAllowed):
		return "account_unavailable"
	case errors.Is(err, oidclogin.ErrLinkMismatch):
		return "link_mismatch"
	case errors.Is(err, oidclogin.ErrIdentityTaken):
		return "identity_taken"
	default:
		return "oidc_failed"
	}
}

// redirectErr leva o navegador a uma tela do SPA com um código de erro fixo.
func (s *Server) redirectErr(w http.ResponseWriter, r *http.Request, path, code string) {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	http.Redirect(w, r, s.cfg.PublicOrigin+path+"?error="+url.QueryEscape(code), http.StatusSeeOther)
}
