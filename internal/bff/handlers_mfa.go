package bff

import (
	"errors"
	"net/http"

	"github.com/Americo509/alo-api/internal/audit"
	"github.com/Americo509/alo-api/internal/identity/mfa"
)

func (s *Server) handleMFAStatus(w http.ResponseWriter, r *http.Request, a *authCtx) {
	enabled, err := s.d.MFA.Enabled(r.Context(), a.User.ID)
	if err != nil {
		s.internal(w, "falha ao consultar o segundo fator", err)
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]bool{"totp_enabled": enabled})
}

// handleTOTPBegin inicia a inscrição e devolve a otpauth URI (o SPA gera o QR).
func (s *Server) handleTOTPBegin(w http.ResponseWriter, r *http.Request, a *authCtx) {
	uri, err := s.d.MFA.BeginEnroll(r.Context(), a.User.ID, a.User.Email)
	switch {
	case errors.Is(err, mfa.ErrAlreadyEnrolled):
		s.problem(w, http.StatusConflict, "conflict")
	case err != nil:
		s.internal(w, "falha ao iniciar o segundo fator", err)
	default:
		s.writeJSON(w, http.StatusOK, map[string]string{"otpauth_uri": uri})
	}
}

// handleTOTPConfirm ativa o fator com o primeiro código e entrega, UMA vez, os
// códigos de recuperação.
func (s *Server) handleTOTPConfirm(w http.ResponseWriter, r *http.Request, a *authCtx) {
	var in struct {
		Code string `json:"code"`
	}
	if !s.decode(w, r, &in) {
		return
	}
	ctx := r.Context()
	rk, acct := rateKey(s.ips.From(r)), s.keyed("mfa-enroll", a.User.ID.String())
	if dec, err := s.d.Guard.Check(ctx, rk, acct); err != nil {
		s.problem(w, http.StatusServiceUnavailable, "service_unavailable")
		return
	} else if !dec.Allow {
		s.tooMany(w, dec.RetryAfter)
		return
	}
	switch err := s.d.MFA.ConfirmEnroll(ctx, a.User.ID, in.Code); {
	case errors.Is(err, mfa.ErrInvalidCode):
		_ = s.d.Guard.Fail(ctx, rk, acct)
		s.problem(w, http.StatusUnauthorized, "invalid_code")
		return
	case errors.Is(err, mfa.ErrAlreadyEnrolled), errors.Is(err, mfa.ErrNotEnrolled):
		s.problem(w, http.StatusConflict, "conflict")
		return
	case err != nil:
		s.internal(w, "falha ao confirmar o segundo fator", err)
		return
	}
	codes, err := s.d.MFA.GenerateRecoveryCodes(ctx, a.User.ID)
	if err != nil {
		s.internal(w, "falha ao gerar códigos de recuperação", err)
		return
	}
	s.record(r, audit.TOTPEnabled, a.User.ID, nil)
	s.record(r, audit.RecoveryCodesCreated, a.User.ID, nil)
	s.writeJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes})
}

func (s *Server) handleTOTPDisable(w http.ResponseWriter, r *http.Request, a *authCtx) {
	if err := s.d.MFA.Disable(r.Context(), a.User.ID); err != nil {
		s.internal(w, "falha ao desativar o segundo fator", err)
		return
	}
	s.record(r, audit.TOTPDisabled, a.User.ID, nil)
	w.WriteHeader(http.StatusNoContent)
}

// handleRecoveryCodes gera um conjunto novo (o anterior deixa de valer).
func (s *Server) handleRecoveryCodes(w http.ResponseWriter, r *http.Request, a *authCtx) {
	enabled, err := s.d.MFA.Enabled(r.Context(), a.User.ID)
	if err != nil {
		s.internal(w, "falha ao consultar o segundo fator", err)
		return
	}
	if !enabled {
		s.problem(w, http.StatusConflict, "conflict")
		return
	}
	codes, err := s.d.MFA.GenerateRecoveryCodes(r.Context(), a.User.ID)
	if err != nil {
		s.internal(w, "falha ao gerar códigos de recuperação", err)
		return
	}
	s.record(r, audit.RecoveryCodesCreated, a.User.ID, nil)
	s.writeJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes})
}
