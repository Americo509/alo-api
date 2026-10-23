package bff

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/Americo509/alo-api/internal/audit"
	"github.com/Americo509/alo-api/internal/identity"
	"github.com/Americo509/alo-api/internal/identity/authflow"
	"github.com/Americo509/alo-api/internal/identity/authtoken"
	"github.com/Americo509/alo-api/internal/identity/mfa"
	"github.com/Americo509/alo-api/internal/identity/pwpolicy"
	"github.com/Americo509/alo-api/internal/identity/session"
)

// passwordProblem traduz erros da política de senha. Devolve true se tratou.
func (s *Server) passwordProblem(w http.ResponseWriter, err error) bool {
	switch {
	case errors.Is(err, pwpolicy.ErrTooShort):
		s.problem(w, http.StatusUnprocessableEntity, "password_too_short")
	case errors.Is(err, pwpolicy.ErrTooLong):
		s.problem(w, http.StatusUnprocessableEntity, "password_too_long")
	case errors.Is(err, pwpolicy.ErrBreached):
		s.problem(w, http.StatusUnprocessableEntity, "password_breached")
	default:
		return false
	}
	return true
}

func (s *Server) internal(w http.ResponseWriter, msg string, err error) {
	s.log.Error(msg, slog.Any("erro", err))
	s.problem(w, http.StatusInternalServerError, "internal")
}

// --- cadastro e verificação -------------------------------------------------------------

// handleRegister: sempre responde 202, exista ou não o e-mail, e só depois do
// tempo mínimo (anti-enumeração por conteúdo e por tempo).
func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !s.decode(w, r, &in) {
		return
	}
	start := s.d.Clock.Now()
	ctx := r.Context()
	if !s.within(w, r, "register-ip", s.cfg.Limits.RegisterIP) {
		return
	}
	email, err := identity.NormalizeEmail(in.Email)
	if err != nil {
		s.problem(w, http.StatusUnprocessableEntity, "invalid_email")
		return
	}
	// Limite por e-mail destino (evita usar a plataforma para encher a caixa de
	// alguém). Estourou: não envia nada, mas responde igual.
	ok, err := s.allow(ctx, "register-email", s.keyed("email", email), s.cfg.Limits.RegisterEmail)
	if err != nil {
		s.log.Error("falha no limitador", slog.Any("erro", err))
		s.problem(w, http.StatusServiceUnavailable, "service_unavailable")
		return
	}
	if ok {
		if err := s.d.Flow.Register(ctx, in.Email, in.Password); err != nil {
			if s.passwordProblem(w, err) {
				return
			}
			s.internal(w, "falha no cadastro", err)
			return
		}
	}
	s.record(r, audit.Registered, uuid.Nil, nil)
	s.floor(ctx, start)
	s.writeJSON(w, http.StatusAccepted, map[string]string{"status": "verification_sent"})
}

func (s *Server) handleVerifyEmail(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token string `json:"token"`
	}
	if !s.decode(w, r, &in) || !s.within(w, r, "verify-ip", s.cfg.Limits.VerifyIP) {
		return
	}
	if err := s.d.Flow.VerifyEmail(r.Context(), in.Token); err != nil {
		if errors.Is(err, authtoken.ErrInvalid) {
			s.problem(w, http.StatusBadRequest, "invalid_token")
			return
		}
		s.internal(w, "falha ao verificar e-mail", err)
		return
	}
	s.record(r, audit.EmailVerified, uuid.Nil, nil)
	w.WriteHeader(http.StatusNoContent)
}

// --- login --------------------------------------------------------------------------------

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email     string `json:"email"`
		Password  string `json:"password"`
		Challenge string `json:"challenge_token"`
	}
	if !s.decode(w, r, &in) {
		return
	}
	ctx := r.Context()
	ip := s.ips.From(r)
	rk := rateKey(ip)
	acct := s.keyed("acct", strings.ToLower(strings.TrimSpace(in.Email)))

	dec, err := s.d.Guard.Check(ctx, rk, acct)
	if err != nil {
		s.log.Error("falha no guard de login", slog.Any("erro", err))
		s.problem(w, http.StatusServiceUnavailable, "service_unavailable")
		return
	}
	if !dec.Allow {
		s.record(r, audit.LoginBlocked, uuid.Nil, nil)
		s.tooMany(w, dec.RetryAfter)
		return
	}
	if dec.Challenge && s.d.Challenger != nil {
		if err := s.d.Challenger.Verify(ctx, in.Challenge, ip); err != nil {
			if errors.Is(err, ErrChallenge) {
				s.problem(w, http.StatusPreconditionRequired, "challenge_required")
			} else {
				s.log.Error("falha no desafio anti-robô", slog.Any("erro", err))
				s.problem(w, http.StatusServiceUnavailable, "service_unavailable")
			}
			return
		}
	}
	if err := s.sleep(ctx, dec.Delay); err != nil {
		return // o cliente desistiu
	}

	u, needsRehash, err := s.d.Flow.Login(ctx, in.Email, in.Password)
	if errors.Is(err, authflow.ErrInvalidCredentials) {
		if ferr := s.d.Guard.Fail(ctx, rk, acct); ferr != nil {
			s.log.Error("falha ao registrar tentativa", slog.Any("erro", ferr))
		}
		s.record(r, audit.LoginFailure, uuid.Nil, nil)
		s.problem(w, http.StatusUnauthorized, "invalid_credentials")
		return
	}
	if err != nil {
		s.internal(w, "falha no login", err)
		return
	}
	if err := s.d.Guard.Success(ctx, rk, acct); err != nil {
		s.log.Error("falha ao zerar contador da conta", slog.Any("erro", err))
	}
	if needsRehash {
		if err := s.d.Flow.Rehash(ctx, u.ID, in.Password); err != nil {
			s.log.Error("falha ao atualizar o hash da senha", slog.Any("erro", err))
		}
	}
	s.completeFirstFactor(w, r, u, "pwd")
}

// completeFirstFactor termina um login depois do primeiro fator: pede o segundo
// ou abre a sessão.
func (s *Server) completeFirstFactor(w http.ResponseWriter, r *http.Request, u identity.User, amr ...string) {
	mfaToken, csrf, err := s.establish(w, r, u, amr...)
	if err != nil {
		s.internal(w, "falha ao abrir a sessão", err)
		return
	}
	if mfaToken != "" {
		s.writeJSON(w, http.StatusOK, map[string]any{
			"mfa_required": true, "mfa_token": mfaToken, "methods": []string{"totp", "recovery_code"},
		})
		return
	}
	s.record(r, audit.LoginSuccess, u.ID, map[string]string{"via": strings.Join(amr, "+")})
	s.writeJSON(w, http.StatusOK, map[string]any{"authenticated": true, "user": toUserJSON(u), "csrf_token": csrf})
}

// handleLoginMFA conclui o login com o segundo fator.
func (s *Server) handleLoginMFA(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token        string `json:"mfa_token"`
		Code         string `json:"code"`
		RecoveryCode string `json:"recovery_code"`
	}
	if !s.decode(w, r, &in) || !s.within(w, r, "mfa-ip", s.cfg.Limits.MFAIP) {
		return
	}
	if in.Code == "" && in.RecoveryCode == "" {
		// Valida antes de consumir o estado: um pedido malformado não queima o login.
		s.problem(w, http.StatusBadRequest, "invalid_request")
		return
	}
	ctx := r.Context()
	p, key, err := s.takePending(ctx, in.Token)
	if err != nil || !s.d.Clock.Now().Before(p.Expires) {
		s.problem(w, http.StatusUnauthorized, "mfa_expired")
		return
	}
	rk, acct := rateKey(s.ips.From(r)), s.keyed("mfa", p.UserID.String())
	dec, err := s.d.Guard.Check(ctx, rk, acct)
	if err != nil {
		s.problem(w, http.StatusServiceUnavailable, "service_unavailable")
		return
	}
	if !dec.Allow {
		s.tooMany(w, dec.RetryAfter)
		return
	}
	if err := s.sleep(ctx, dec.Delay); err != nil {
		return
	}

	usedRecovery := false
	switch {
	case in.Code != "":
		err = s.d.MFA.Verify(ctx, p.UserID, in.Code)
	case in.RecoveryCode != "":
		usedRecovery = true
		_, err = s.d.MFA.UseRecoveryCode(ctx, p.UserID, in.RecoveryCode)
	default:
		s.problem(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if err != nil {
		if !errors.Is(err, mfa.ErrInvalidCode) {
			s.internal(w, "falha ao verificar o segundo fator", err)
			return
		}
		_ = s.d.Guard.Fail(ctx, rk, acct)
		s.record(r, audit.MFAFailure, p.UserID, nil)
		if p.Attempts++; p.Attempts < maxMFAAttempts {
			if perr := s.putPending(ctx, key, p); perr != nil {
				s.log.Error("falha ao devolver o estado de MFA", slog.Any("erro", perr))
			}
		}
		s.problem(w, http.StatusUnauthorized, "invalid_code")
		return
	}
	_ = s.d.Guard.Success(ctx, rk, acct)

	u, err := s.d.Users.GetUser(ctx, p.UserID)
	if err != nil || !u.CanLogIn() {
		s.problem(w, http.StatusForbidden, "account_unavailable")
		return
	}
	amr := append(append([]string{}, p.AMR...), factorsAfterSecond)
	if usedRecovery {
		amr = append(amr, "recovery")
		s.record(r, audit.RecoveryCodeUsed, u.ID, nil)
	}
	csrf, err := s.startSession(w, r, u, amr...)
	if err != nil {
		s.internal(w, "falha ao abrir a sessão", err)
		return
	}
	s.record(r, audit.MFASuccess, u.ID, nil)
	s.record(r, audit.LoginSuccess, u.ID, map[string]string{"via": strings.Join(amr, "+")})
	s.writeJSON(w, http.StatusOK, map[string]any{"authenticated": true, "user": toUserJSON(u), "csrf_token": csrf})
}

// --- recuperação de senha ----------------------------------------------------------------

// handleForgot: sempre 202, no mesmo tempo, exista ou não a conta.
func (s *Server) handleForgot(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Email string `json:"email"`
	}
	if !s.decode(w, r, &in) {
		return
	}
	start := s.d.Clock.Now()
	ctx := r.Context()
	if !s.within(w, r, "forgot-ip", s.cfg.Limits.ForgotIP) {
		return
	}
	if email, err := identity.NormalizeEmail(in.Email); err == nil {
		ok, err := s.allow(ctx, "forgot-email", s.keyed("email", email), s.cfg.Limits.ForgotEmail)
		if err != nil {
			s.problem(w, http.StatusServiceUnavailable, "service_unavailable")
			return
		}
		if ok {
			if err := s.d.Flow.StartPasswordRecovery(ctx, email); err != nil {
				s.log.Error("falha ao iniciar a recuperação", slog.Any("erro", err))
			}
		}
	}
	s.record(r, audit.PasswordResetRequested, uuid.Nil, nil)
	s.floor(ctx, start)
	s.writeJSON(w, http.StatusAccepted, map[string]string{"status": "if_account_exists_email_sent"})
}

func (s *Server) handleReset(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if !s.decode(w, r, &in) || !s.within(w, r, "verify-ip", s.cfg.Limits.VerifyIP) {
		return
	}
	uid, err := s.d.Flow.CompletePasswordRecovery(r.Context(), in.Token, in.Password)
	if err != nil {
		switch {
		case errors.Is(err, authtoken.ErrInvalid):
			s.problem(w, http.StatusBadRequest, "invalid_token")
		case s.passwordProblem(w, err):
		default:
			s.internal(w, "falha ao redefinir a senha", err)
		}
		return
	}
	// Senha trocada por quem tem o e-mail: derruba todas as sessões antigas.
	if err := s.d.Sessions.RevokeAll(r.Context(), uid); err != nil {
		s.log.Error("falha ao encerrar sessões após a recuperação", slog.Any("erro", err))
	}
	s.record(r, audit.PasswordResetCompleted, uid, nil)
	w.WriteHeader(http.StatusNoContent)
}

// --- sessão ---------------------------------------------------------------------------------

// handleSession informa o estado da sessão (e o token CSRF) ao SPA.
func (s *Server) handleSession(w http.ResponseWriter, r *http.Request) {
	a, err := s.peek(w, r)
	if err != nil {
		s.problem(w, http.StatusServiceUnavailable, "service_unavailable")
		return
	}
	if a == nil {
		s.writeJSON(w, http.StatusOK, map[string]any{"authenticated": false})
		return
	}
	enabled, err := s.d.MFA.Enabled(r.Context(), a.User.ID)
	if err != nil {
		s.problem(w, http.StatusServiceUnavailable, "service_unavailable")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{
		"authenticated":          true,
		"user":                   toUserJSON(a.User),
		"csrf_token":             s.csrfToken(a.SessionID),
		"amr":                    a.Data.AMR,
		"mfa_enabled":            enabled,
		"recently_authenticated": s.d.Sessions.Fresh(a.Data, s.cfg.ReauthMaxAge),
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request, a *authCtx) {
	if err := s.d.Sessions.Revoke(r.Context(), a.SessionID); err != nil {
		s.internal(w, "falha ao encerrar a sessão", err)
		return
	}
	session.ClearCookie(w)
	s.record(r, audit.Logout, a.User.ID, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleLogoutAll(w http.ResponseWriter, r *http.Request, a *authCtx) {
	if err := s.d.Sessions.RevokeAll(r.Context(), a.User.ID); err != nil {
		s.internal(w, "falha ao encerrar as sessões", err)
		return
	}
	session.ClearCookie(w)
	s.record(r, audit.LogoutAll, a.User.ID, nil)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleSessionsList(w http.ResponseWriter, r *http.Request, a *authCtx) {
	list, err := s.d.Sessions.List(r.Context(), a.User.ID)
	if err != nil {
		s.internal(w, "falha ao listar sessões", err)
		return
	}
	current, _ := session.HandleOf(a.SessionID)
	type item struct {
		Handle     string    `json:"handle"`
		Current    bool      `json:"current"`
		CreatedAt  time.Time `json:"created_at"`
		LastSeenAt time.Time `json:"last_seen_at"`
		IP         string    `json:"ip,omitempty"`
		UserAgent  string    `json:"user_agent,omitempty"`
	}
	out := make([]item, 0, len(list))
	for _, i := range list {
		out = append(out, item{i.Handle, i.Handle == current, i.CreatedAt, i.LastSeenAt, i.IP, i.UserAgent})
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"sessions": out})
}

func (s *Server) handleSessionRevoke(w http.ResponseWriter, r *http.Request, a *authCtx) {
	handle := r.PathValue("handle")
	err := s.d.Sessions.RevokeHandle(r.Context(), a.User.ID, handle)
	if errors.Is(err, session.ErrNotFound) {
		s.problem(w, http.StatusNotFound, "not_found")
		return
	}
	if err != nil {
		s.internal(w, "falha ao encerrar a sessão", err)
		return
	}
	if current, _ := session.HandleOf(a.SessionID); current == handle {
		session.ClearCookie(w)
	}
	s.record(r, audit.SessionRevoked, a.User.ID, nil)
	w.WriteHeader(http.StatusNoContent)
}

// handleReauth confirma a identidade para liberar ações sensíveis, com senha ou
// segundo fator, sob o mesmo guard contra força bruta.
func (s *Server) handleReauth(w http.ResponseWriter, r *http.Request, a *authCtx) {
	var in struct {
		Password     string `json:"password"`
		Code         string `json:"code"`
		RecoveryCode string `json:"recovery_code"`
	}
	if !s.decode(w, r, &in) {
		return
	}
	ctx := r.Context()
	rk, acct := rateKey(s.ips.From(r)), s.keyed("reauth", a.User.ID.String())
	dec, err := s.d.Guard.Check(ctx, rk, acct)
	if err != nil {
		s.problem(w, http.StatusServiceUnavailable, "service_unavailable")
		return
	}
	if !dec.Allow {
		s.tooMany(w, dec.RetryAfter)
		return
	}
	if err := s.sleep(ctx, dec.Delay); err != nil {
		return
	}

	factor := "pwd"
	switch {
	case in.Password != "":
		err = s.d.Flow.VerifyPassword(ctx, a.User.ID, in.Password)
	case in.Code != "":
		factor = "mfa"
		err = s.d.MFA.Verify(ctx, a.User.ID, in.Code)
	case in.RecoveryCode != "":
		factor = "recovery"
		_, err = s.d.MFA.UseRecoveryCode(ctx, a.User.ID, in.RecoveryCode)
	default:
		s.problem(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if errors.Is(err, authflow.ErrInvalidCredentials) || errors.Is(err, mfa.ErrInvalidCode) || errors.Is(err, mfa.ErrNotEnrolled) {
		_ = s.d.Guard.Fail(ctx, rk, acct)
		s.problem(w, http.StatusUnauthorized, "invalid_credentials")
		return
	}
	if err != nil {
		s.internal(w, "falha na reautenticação", err)
		return
	}
	_ = s.d.Guard.Success(ctx, rk, acct)
	if _, err := s.d.Sessions.Reauth(ctx, a.SessionID, factor); err != nil {
		s.internal(w, "falha ao renovar a autenticação", err)
		return
	}
	s.record(r, audit.Reauthenticated, a.User.ID, map[string]string{"via": factor})
	w.WriteHeader(http.StatusNoContent)
}

// handlePasswordChange troca a senha (autenticação recente + senha atual),
// encerra as outras sessões e troca o ID da sessão atual.
func (s *Server) handlePasswordChange(w http.ResponseWriter, r *http.Request, a *authCtx) {
	var in struct {
		Current string `json:"current_password"`
		New     string `json:"new_password"`
	}
	if !s.decode(w, r, &in) {
		return
	}
	ctx := r.Context()
	rk, acct := rateKey(s.ips.From(r)), s.keyed("pwchange", a.User.ID.String())
	if dec, err := s.d.Guard.Check(ctx, rk, acct); err != nil {
		s.problem(w, http.StatusServiceUnavailable, "service_unavailable")
		return
	} else if !dec.Allow {
		s.tooMany(w, dec.RetryAfter)
		return
	}
	if err := s.d.Flow.ChangePassword(ctx, a.User.ID, in.Current, in.New); err != nil {
		switch {
		case errors.Is(err, authflow.ErrInvalidCredentials):
			_ = s.d.Guard.Fail(ctx, rk, acct)
			s.problem(w, http.StatusUnauthorized, "invalid_credentials")
		case s.passwordProblem(w, err):
		default:
			s.internal(w, "falha ao trocar a senha", err)
		}
		return
	}
	if err := s.d.Sessions.RevokeAllExcept(ctx, a.User.ID, a.SessionID); err != nil {
		s.log.Error("falha ao encerrar as outras sessões", slog.Any("erro", err))
	}
	// Mudança de privilégio: novo ID de sessão (anti-fixação).
	newID, _, err := s.d.Sessions.Rotate(ctx, a.SessionID)
	if err != nil {
		s.internal(w, "falha ao renovar a sessão", err)
		return
	}
	session.SetCookie(w, newID)
	s.record(r, audit.PasswordChanged, a.User.ID, nil)
	s.writeJSON(w, http.StatusOK, map[string]string{"csrf_token": s.csrfToken(newID)})
}
