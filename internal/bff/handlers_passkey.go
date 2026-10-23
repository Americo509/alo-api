package bff

import (
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/Americo509/alo-api/internal/audit"
	"github.com/Americo509/alo-api/internal/identity/passkey"
)

// A cerimônia viaja num cabeçalho porque o corpo da requisição é a resposta do
// autenticador, que a biblioteca WebAuthn lê direto.
const ceremonyHeader = "X-Passkey-Ceremony"

func (s *Server) handlePasskeyRegisterBegin(w http.ResponseWriter, r *http.Request, a *authCtx) {
	opts, token, err := s.d.Passkeys.BeginRegistration(r.Context(), a.User.ID)
	switch {
	case errors.Is(err, passkey.ErrLimit):
		s.problem(w, http.StatusConflict, "conflict")
	case errors.Is(err, passkey.ErrUserNotAllowed):
		s.problem(w, http.StatusForbidden, "account_unavailable")
	case err != nil:
		s.internal(w, "falha ao iniciar o cadastro da passkey", err)
	default:
		s.writeJSON(w, http.StatusOK, map[string]any{"options": opts, "ceremony": token})
	}
}

// cleanLabel limpa o apelido da passkey (texto do usuário).
func cleanLabel(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == utf8.RuneError {
			return -1
		}
		return r
	}, strings.TrimSpace(s))
	if utf8.RuneCountInString(s) > 100 {
		s = string([]rune(s)[:100])
	}
	return s
}

func (s *Server) handlePasskeyRegisterFinish(w http.ResponseWriter, r *http.Request, a *authCtx) {
	token := r.Header.Get(ceremonyHeader)
	label := cleanLabel(r.URL.Query().Get("label"))
	err := s.d.Passkeys.FinishRegistration(r.Context(), a.User.ID, token, r, label)
	switch {
	case err == nil:
		s.record(r, audit.PasskeyAdded, a.User.ID, nil)
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, passkey.ErrLimit), errors.Is(err, passkey.ErrDuplicate):
		s.problem(w, http.StatusConflict, "conflict")
	case errors.Is(err, passkey.ErrCeremony), errors.Is(err, passkey.ErrNotVerified):
		s.problem(w, http.StatusBadRequest, "passkey_failed")
	default:
		s.internal(w, "falha ao concluir o cadastro da passkey", err)
	}
}

func (s *Server) handlePasskeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	if !s.within(w, r, "passkey-ip", s.cfg.Limits.PasskeyBeginIP) {
		return
	}
	opts, token, err := s.d.Passkeys.BeginLogin(r.Context())
	if err != nil {
		s.internal(w, "falha ao iniciar o login por passkey", err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"options": opts, "ceremony": token})
}

// handlePasskeyLoginFinish: a passkey com verificação do usuário já é um
// segundo fator embutido (algo que se tem + biometria/PIN), então não pede TOTP.
func (s *Server) handlePasskeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	if !s.within(w, r, "passkey-ip", s.cfg.Limits.PasskeyBeginIP) {
		return
	}
	u, err := s.d.Passkeys.FinishLogin(r.Context(), r.Header.Get(ceremonyHeader), r)
	switch {
	case errors.Is(err, passkey.ErrCloned):
		s.record(r, audit.PasskeyCloneSuspected, uuid.Nil, nil)
		s.problem(w, http.StatusUnauthorized, "passkey_failed")
		return
	case errors.Is(err, passkey.ErrUserNotAllowed):
		s.problem(w, http.StatusForbidden, "account_unavailable")
		return
	case errors.Is(err, passkey.ErrCeremony), errors.Is(err, passkey.ErrNotVerified), errors.Is(err, passkey.ErrNotFound):
		s.record(r, audit.LoginFailure, uuid.Nil, map[string]string{"via": "passkey"})
		s.problem(w, http.StatusUnauthorized, "passkey_failed")
		return
	case err != nil:
		s.internal(w, "falha no login por passkey", err)
		return
	}
	csrf, err := s.startSession(w, r, u, "passkey", "uv")
	if err != nil {
		s.internal(w, "falha ao abrir a sessão", err)
		return
	}
	s.record(r, audit.PasskeyLogin, u.ID, nil)
	s.record(r, audit.LoginSuccess, u.ID, map[string]string{"via": "passkey"})
	s.writeJSON(w, http.StatusOK, map[string]any{"authenticated": true, "user": toUserJSON(u), "csrf_token": csrf})
}

func (s *Server) handlePasskeysList(w http.ResponseWriter, r *http.Request, a *authCtx) {
	list, err := s.d.Passkeys.List(r.Context(), a.User.ID)
	if err != nil {
		s.internal(w, "falha ao listar passkeys", err)
		return
	}
	type item struct {
		ID         string     `json:"id"`
		Label      string     `json:"label"`
		CreatedAt  time.Time  `json:"created_at"`
		LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	}
	out := make([]item, 0, len(list))
	for _, p := range list {
		it := item{ID: b64.EncodeToString(p.Credential.ID), Label: p.Label, CreatedAt: p.CreatedAt}
		if !p.LastUsedAt.IsZero() {
			t := p.LastUsedAt
			it.LastUsedAt = &t
		}
		out = append(out, it)
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"passkeys": out})
}

func (s *Server) handlePasskeyRemove(w http.ResponseWriter, r *http.Request, a *authCtx) {
	id, err := b64.DecodeString(r.PathValue("id"))
	if err != nil || len(id) == 0 {
		s.problem(w, http.StatusNotFound, "not_found")
		return
	}
	switch err := s.d.Passkeys.Remove(r.Context(), a.User.ID, id); {
	case errors.Is(err, passkey.ErrNotFound):
		s.problem(w, http.StatusNotFound, "not_found")
	case err != nil:
		s.internal(w, "falha ao remover a passkey", err)
	default:
		s.record(r, audit.PasskeyRemoved, a.User.ID, nil)
		w.WriteHeader(http.StatusNoContent)
	}
}
