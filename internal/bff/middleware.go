package bff

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/Americo509/alo-api/internal/audit"
	"github.com/Americo509/alo-api/internal/identity"
	"github.com/Americo509/alo-api/internal/identity/ephemeral"
	"github.com/Americo509/alo-api/internal/identity/session"
)

// authCtx é o usuário autenticado da requisição.
type authCtx struct {
	User      identity.User
	Data      session.Data
	SessionID string
}

type authedHandler func(w http.ResponseWriter, r *http.Request, a *authCtx)

// recoverer evita que um panic derrube o processo ou vaze detalhes ao cliente.
func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				// Nunca registra o corpo nem cabeçalhos: podem ter senha ou cookie.
				s.log.Error("panic em handler", slog.String("rota", r.Method+" "+r.URL.Path), slog.Any("panic", rec))
				s.problem(w, http.StatusInternalServerError, "internal")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// public protege rotas sem sessão: a origem tem de ser a do painel.
func (s *Server) public(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.originAllowed(r) {
			s.problem(w, http.StatusForbidden, "forbidden_origin")
			return
		}
		h(w, r)
	}
}

// peek devolve o usuário autenticado ou nil, sem escrever resposta.
func (s *Server) peek(w http.ResponseWriter, r *http.Request) (*authCtx, error) {
	id, ok := session.IDFromRequest(r)
	if !ok {
		return nil, nil
	}
	d, err := s.d.Sessions.Get(r.Context(), id)
	if errors.Is(err, session.ErrNotFound) {
		session.ClearCookie(w)
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	u, err := s.d.Users.GetUser(r.Context(), d.UserID)
	if err != nil || !u.CanLogIn() {
		_ = s.d.Sessions.Revoke(r.Context(), id)
		session.ClearCookie(w)
		return nil, nil //nolint:nilerr // conta removida/suspensa: tratada como sem sessão
	}
	return &authCtx{User: u, Data: d, SessionID: id}, nil
}

// authed exige sessão válida e, em requisições que alteram estado, origem do
// painel e token CSRF.
func (s *Server) authed(h authedHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.originAllowed(r) {
			s.problem(w, http.StatusForbidden, "forbidden_origin")
			return
		}
		a, err := s.peek(w, r)
		if err != nil {
			s.log.Error("falha ao validar a sessão", slog.Any("erro", err))
			s.problem(w, http.StatusServiceUnavailable, "service_unavailable")
			return
		}
		if a == nil {
			s.problem(w, http.StatusUnauthorized, "unauthenticated")
			return
		}
		if isUnsafe(r.Method) && !s.csrfValid(r, a.SessionID) {
			s.problem(w, http.StatusForbidden, "csrf_invalid")
			return
		}
		h(w, r, a)
	}
}

// fresh, além de authed, exige autenticação forte recente (ação sensível).
func (s *Server) fresh(h authedHandler) http.HandlerFunc {
	return s.authed(func(w http.ResponseWriter, r *http.Request, a *authCtx) {
		if !s.d.Sessions.Fresh(a.Data, s.cfg.ReauthMaxAge) {
			s.problem(w, http.StatusUnauthorized, "reauth_required")
			return
		}
		h(w, r, a)
	})
}

// --- auditoria -------------------------------------------------------------------------

// record grava o evento sem deixar a falha derrubar a requisição.
func (s *Server) record(r *http.Request, typ audit.Type, userID uuid.UUID, meta map[string]string) {
	ctx := context.WithoutCancel(r.Context())
	err := s.d.Audit.Record(ctx, audit.Event{
		Type: typ, UserID: userID, IP: s.ips.From(r), UserAgent: r.UserAgent(), Meta: meta,
	})
	if err != nil {
		s.log.Error("falha ao gravar evento de segurança", slog.String("evento", string(typ)), slog.Any("erro", err))
	}
}

// --- limites -----------------------------------------------------------------------------

// keyed devolve HMAC(chave do servidor, rótulo+valor): chaves de limite sem
// guardar e-mail em claro no Redis e sem permitir dicionário offline.
func (s *Server) keyed(label, value string) string {
	m := hmac.New(sha256.New, s.cfg.KeyedHashKey)
	m.Write([]byte(label + ":" + value))
	return hex.EncodeToString(m.Sum(nil))
}

// allow conta um evento e informa se continua dentro do limite.
func (s *Server) allow(ctx context.Context, bucket, key string, rule Rule) (bool, error) {
	n, err := s.d.Counter.Incr(ctx, "rl:"+bucket+":"+key, rule.Window)
	if err != nil {
		return false, err
	}
	return n <= rule.Max, nil
}

// within aplica um limite por IP e responde 429/503 sozinho.
func (s *Server) within(w http.ResponseWriter, r *http.Request, bucket string, rule Rule) bool {
	ok, err := s.allow(r.Context(), bucket, rateKey(s.ips.From(r)), rule)
	if err != nil {
		s.log.Error("falha no limitador", slog.Any("erro", err))
		s.problem(w, http.StatusServiceUnavailable, "service_unavailable")
		return false
	}
	if !ok {
		s.tooMany(w, rule.Window)
		return false
	}
	return true
}

func (s *Server) tooMany(w http.ResponseWriter, retry time.Duration) {
	w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())))
	s.problem(w, http.StatusTooManyRequests, "too_many_requests")
}

// --- tempo --------------------------------------------------------------------------------

func (s *Server) sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	select {
	case <-s.d.Clock.After(d):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// floor espera até completar o tempo mínimo de resposta desde start.
func (s *Server) floor(ctx context.Context, start time.Time) {
	_ = s.sleep(ctx, s.cfg.ResponseFloor-s.d.Clock.Now().Sub(start))
}

// --- sessão e segundo fator pendente ---------------------------------------------------

type userJSON struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	DisplayName   string `json:"display_name,omitempty"`
}

func toUserJSON(u identity.User) userJSON {
	return userJSON{ID: u.ID.String(), Email: u.Email, EmailVerified: u.EmailVerified, DisplayName: u.DisplayName}
}

// startSession cria a sessão, grava o cookie e devolve o token CSRF.
func (s *Server) startSession(w http.ResponseWriter, r *http.Request, u identity.User, amr ...string) (string, error) {
	id, _, err := s.d.Sessions.CreateWithMeta(r.Context(), u.ID,
		session.Meta{IP: s.ips.From(r), UserAgent: r.UserAgent()}, amr...)
	if err != nil {
		return "", err
	}
	session.SetCookie(w, id)
	return s.csrfToken(id), nil
}

type pendingMFA struct {
	UserID   uuid.UUID `json:"u"`
	AMR      []string  `json:"a"`
	Attempts int       `json:"n"`
	Expires  time.Time `json:"e"`
}

const (
	pendingPrefix      = "mfa-pending:"
	maxMFAAttempts     = 5
	factorsAfterSecond = "mfa" // vai no AMR da sessão depois do segundo fator
)

func (s *Server) putPending(ctx context.Context, key string, p pendingMFA) error {
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	ttl := p.Expires.Sub(s.d.Clock.Now())
	if ttl <= 0 {
		return nil
	}
	return s.d.Ephemeral.Put(ctx, pendingPrefix+key, raw, ttl)
}

// newPending guarda o primeiro fator já aprovado e devolve o token do segundo.
func (s *Server) newPending(ctx context.Context, userID uuid.UUID, amr []string) (string, error) {
	token, key, err := ephemeral.NewToken(nil)
	if err != nil {
		return "", err
	}
	p := pendingMFA{UserID: userID, AMR: amr, Expires: s.d.Clock.Now().Add(s.cfg.MFAPendingTTL)}
	if err := s.putPending(ctx, key, p); err != nil {
		return "", err
	}
	return token, nil
}

// takePending consome o estado pendente. O chamador devolve com putPending se a
// tentativa falhar (e ainda houver tentativas), o que serializa tentativas
// paralelas: só uma requisição por vez tem o estado em mãos.
func (s *Server) takePending(ctx context.Context, token string) (pendingMFA, string, error) {
	key, err := ephemeral.KeyOf(token)
	if err != nil {
		return pendingMFA{}, "", ephemeral.ErrNotFound
	}
	raw, err := s.d.Ephemeral.Take(ctx, pendingPrefix+key)
	if err != nil {
		return pendingMFA{}, "", err
	}
	var p pendingMFA
	if err := json.Unmarshal(raw, &p); err != nil {
		return pendingMFA{}, "", fmt.Errorf("bff: estado de MFA corrompido: %w", err)
	}
	return p, key, nil
}

// establish conclui o primeiro fator. Se o usuário tem segundo fator, devolve o
// token do segundo e NÃO cria sessão; senão cria a sessão e devolve o CSRF.
func (s *Server) establish(w http.ResponseWriter, r *http.Request, u identity.User, amr ...string) (mfaToken, csrf string, err error) {
	enabled, err := s.d.MFA.Enabled(r.Context(), u.ID)
	if err != nil {
		return "", "", err
	}
	if enabled {
		mfaToken, err = s.newPending(r.Context(), u.ID, amr)
		return mfaToken, "", err
	}
	csrf, err = s.startSession(w, r, u, amr...)
	return "", csrf, err
}
