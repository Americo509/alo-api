package bff

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"

	"github.com/Americo509/alo-api/internal/audit"
	"github.com/Americo509/alo-api/internal/clock"
	"github.com/Americo509/alo-api/internal/identity"
	"github.com/Americo509/alo-api/internal/identity/authflow"
	"github.com/Americo509/alo-api/internal/identity/authtoken"
	"github.com/Americo509/alo-api/internal/identity/ephemeral"
	"github.com/Americo509/alo-api/internal/identity/loginguard"
	"github.com/Americo509/alo-api/internal/identity/mfa"
	"github.com/Americo509/alo-api/internal/identity/oidclogin"
	"github.com/Americo509/alo-api/internal/identity/passkey"
	"github.com/Americo509/alo-api/internal/identity/pwpolicy"
	"github.com/Americo509/alo-api/internal/identity/session"
)

const (
	panelOrigin = "https://app.alo.test"
	goodPW      = "senha-bem-grande-123"
	newPW       = "outra-senha-bem-grande-456"
	totpOK      = "718293"
	recoveryOK  = "abcd-efgh-ijkl"
)

var (
	ctx = context.Background()
	t0  = time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
)

// --- usuários e fluxo de senha (dublê) ---------------------------------------------------

type userDB struct {
	mu    sync.Mutex
	byID  map[uuid.UUID]identity.User
	pw    map[uuid.UUID]string
	email map[string]uuid.UUID
}

func newUserDB() *userDB {
	return &userDB{byID: map[uuid.UUID]identity.User{}, pw: map[uuid.UUID]string{}, email: map[string]uuid.UUID{}}
}

func (d *userDB) GetUser(_ context.Context, id uuid.UUID) (identity.User, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	u, ok := d.byID[id]
	if !ok {
		return identity.User{}, identity.ErrNotFound
	}
	return u, nil
}

func (d *userDB) add(email, pw string) identity.User {
	d.mu.Lock()
	defer d.mu.Unlock()
	u := identity.User{ID: uuid.New(), Email: email, EmailVerified: true, Status: identity.StatusActive}
	d.byID[u.ID] = u
	d.pw[u.ID] = pw
	d.email[email] = u.ID
	return u
}

func (d *userDB) setStatus(id uuid.UUID, s identity.Status) {
	d.mu.Lock()
	defer d.mu.Unlock()
	u := d.byID[id]
	u.Status = s
	d.byID[id] = u
}

type fakeFlow struct {
	db *userDB

	mu            sync.Mutex
	registerCalls []string
	recoveryCalls []string
	rehashCalls   []uuid.UUID
	verifyTokens  map[string]bool
	resetTokens   map[string]uuid.UUID
	needsRehash   bool
	loginCalls    int
	registerErr   error
}

func newFakeFlow(db *userDB) *fakeFlow {
	return &fakeFlow{db: db, verifyTokens: map[string]bool{}, resetTokens: map[string]uuid.UUID{}}
}

func (f *fakeFlow) Register(_ context.Context, email, password string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.registerErr != nil {
		return f.registerErr
	}
	if len([]rune(password)) < 12 {
		return pwpolicy.ErrTooShort
	}
	f.registerCalls = append(f.registerCalls, email)
	return nil
}

func (f *fakeFlow) VerifyEmail(_ context.Context, token string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.verifyTokens[token] {
		return authtoken.ErrInvalid
	}
	delete(f.verifyTokens, token)
	return nil
}

func (f *fakeFlow) Login(_ context.Context, email, password string) (identity.User, bool, error) {
	f.mu.Lock()
	f.loginCalls++
	rehash := f.needsRehash
	f.mu.Unlock()
	f.db.mu.Lock()
	defer f.db.mu.Unlock()
	id, ok := f.db.email[strings.ToLower(strings.TrimSpace(email))]
	if !ok || f.db.pw[id] != password || f.db.byID[id].Status != identity.StatusActive {
		return identity.User{}, false, authflow.ErrInvalidCredentials
	}
	return f.db.byID[id], rehash, nil
}

func (f *fakeFlow) Rehash(_ context.Context, id uuid.UUID, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rehashCalls = append(f.rehashCalls, id)
	return nil
}

func (f *fakeFlow) VerifyPassword(_ context.Context, id uuid.UUID, password string) error {
	f.db.mu.Lock()
	defer f.db.mu.Unlock()
	if f.db.pw[id] != password {
		return authflow.ErrInvalidCredentials
	}
	return nil
}

func (f *fakeFlow) ChangePassword(ctx context.Context, id uuid.UUID, cur, next string) error {
	if err := f.VerifyPassword(ctx, id, cur); err != nil {
		return err
	}
	if len([]rune(next)) < 12 {
		return pwpolicy.ErrTooShort
	}
	f.db.mu.Lock()
	defer f.db.mu.Unlock()
	f.db.pw[id] = next
	return nil
}

func (f *fakeFlow) StartPasswordRecovery(_ context.Context, email string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.recoveryCalls = append(f.recoveryCalls, email)
	return nil
}

func (f *fakeFlow) CompletePasswordRecovery(_ context.Context, token, password string) (uuid.UUID, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id, ok := f.resetTokens[token]
	if !ok {
		return uuid.Nil, authtoken.ErrInvalid
	}
	if len([]rune(password)) < 12 {
		return uuid.Nil, pwpolicy.ErrTooShort
	}
	delete(f.resetTokens, token)
	f.db.mu.Lock()
	f.db.pw[id] = password
	f.db.mu.Unlock()
	return id, nil
}

// --- MFA, passkeys e OIDC (dublês) --------------------------------------------------------------

type fakeMFA struct {
	mu       sync.Mutex
	enabled  map[uuid.UUID]bool
	recovery map[uuid.UUID]map[string]bool
}

func newFakeMFA() *fakeMFA {
	return &fakeMFA{enabled: map[uuid.UUID]bool{}, recovery: map[uuid.UUID]map[string]bool{}}
}

func (m *fakeMFA) enable(id uuid.UUID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.enabled[id] = true
	m.recovery[id] = map[string]bool{recoveryOK: true}
}

func (m *fakeMFA) Enabled(_ context.Context, id uuid.UUID) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.enabled[id], nil
}

func (m *fakeMFA) BeginEnroll(_ context.Context, id uuid.UUID, account string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.enabled[id] {
		return "", mfa.ErrAlreadyEnrolled
	}
	return "otpauth://totp/Alo:" + account + "?secret=ABC", nil
}

func (m *fakeMFA) ConfirmEnroll(_ context.Context, id uuid.UUID, code string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.enabled[id] {
		return mfa.ErrAlreadyEnrolled
	}
	if code != totpOK {
		return mfa.ErrInvalidCode
	}
	m.enabled[id] = true
	return nil
}

func (m *fakeMFA) Verify(_ context.Context, id uuid.UUID, code string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.enabled[id] {
		return mfa.ErrNotEnrolled
	}
	if code != totpOK {
		return mfa.ErrInvalidCode
	}
	return nil
}

func (m *fakeMFA) Disable(_ context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.enabled, id)
	delete(m.recovery, id)
	return nil
}

func (m *fakeMFA) GenerateRecoveryCodes(_ context.Context, id uuid.UUID) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	codes := []string{"aaaa-bbbb-cccc", "dddd-eeee-ffff"}
	m.recovery[id] = map[string]bool{codes[0]: true, codes[1]: true}
	return codes, nil
}

func (m *fakeMFA) UseRecoveryCode(_ context.Context, id uuid.UUID, code string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.recovery[id][code] {
		return 0, mfa.ErrInvalidCode
	}
	delete(m.recovery[id], code)
	return len(m.recovery[id]), nil
}

type fakePasskeys struct {
	mu           sync.Mutex
	user         identity.User
	loginErr     error
	finishRegErr error
	regToken     string
	regLabel     string
	loginToken   string
	stored       []passkey.Stored
}

func (p *fakePasskeys) BeginRegistration(_ context.Context, _ uuid.UUID) (*protocol.CredentialCreation, string, error) {
	return &protocol.CredentialCreation{}, "ceremony-reg", nil
}

func (p *fakePasskeys) FinishRegistration(_ context.Context, _ uuid.UUID, token string, _ *http.Request, label string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.regToken, p.regLabel = token, label
	return p.finishRegErr
}

func (p *fakePasskeys) BeginLogin(_ context.Context) (*protocol.CredentialAssertion, string, error) {
	return &protocol.CredentialAssertion{}, "ceremony-login", nil
}

func (p *fakePasskeys) FinishLogin(_ context.Context, token string, _ *http.Request) (identity.User, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.loginToken = token
	return p.user, p.loginErr
}

func (p *fakePasskeys) List(_ context.Context, userID uuid.UUID) ([]passkey.Stored, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var out []passkey.Stored
	for _, s := range p.stored {
		if s.UserID == userID {
			out = append(out, s)
		}
	}
	return out, nil
}

func (p *fakePasskeys) Remove(_ context.Context, userID uuid.UUID, id []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, s := range p.stored {
		if s.UserID == userID && string(s.Credential.ID) == string(id) {
			p.stored = append(p.stored[:i], p.stored[i+1:]...)
			return nil
		}
	}
	return passkey.ErrNotFound
}

type fakeOIDC struct {
	mu        sync.Mutex
	crossSite bool
	result    oidclogin.Result
	err       error
	begun     []struct {
		Provider string
		Intent   oidclogin.Intent
		Link     uuid.UUID
	}
	got []oidclogin.CallbackInput
}

func (o *fakeOIDC) Begin(_ context.Context, provider string, intent oidclogin.Intent, link uuid.UUID) (oidclogin.BeginResult, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if provider != "google" && provider != "apple" {
		return oidclogin.BeginResult{}, oidclogin.ErrUnknownProvider
	}
	o.begun = append(o.begun, struct {
		Provider string
		Intent   oidclogin.Intent
		Link     uuid.UUID
	}{provider, intent, link})
	return oidclogin.BeginResult{AuthURL: "https://idp.example/authorize?state=abc", Binding: "binding-xyz", CrossSite: o.crossSite}, nil
}

func (o *fakeOIDC) Callback(_ context.Context, in oidclogin.CallbackInput) (oidclogin.Result, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.got = append(o.got, in)
	return o.result, o.err
}

type fakeChallenger struct {
	mu    sync.Mutex
	valid string
	err   error
	calls []string
}

func (c *fakeChallenger) Verify(_ context.Context, token, _ string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, token)
	if c.err != nil {
		return c.err
	}
	if token != c.valid || token == "" {
		return ErrChallenge
	}
	return nil
}

// --- ambiente --------------------------------------------------------------------------------------

type env struct {
	srv     *Server
	h       http.Handler
	clk     *clock.Fake
	users   *userDB
	flow    *fakeFlow
	mfa     *fakeMFA
	pk      *fakePasskeys
	oidc    *fakeOIDC
	sess    *session.Manager
	guard   *loginguard.Guard
	counter *loginguard.MemoryCounter
	eph     *ephemeral.Memory
	aud     *audit.Memory
	chal    *fakeChallenger
	logs    *bytes.Buffer
}

func key32(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

// noDelayGuard: sem atraso progressivo, para os testes não esperarem o relógio.
// Desafio após 5 falhas, bloqueio de IP após 10.
func noDelayGuard() loginguard.Config {
	return loginguard.Config{
		Window: 15 * time.Minute, DelayAfter: 3, DelayStep: 0, MaxDelay: 0,
		ChallengeAfter: 5, BlockAfterIP: 10, GlobalWindow: time.Minute, GlobalStuffingThreshold: 1000,
	}
}

func newEnv(t *testing.T, mutate ...func(*Config)) *env {
	t.Helper()
	return buildEnv(t, noDelayGuard(), mutate...)
}

func buildEnv(t *testing.T, gcfg loginguard.Config, mutate ...func(*Config)) *env {
	t.Helper()
	clk := clock.NewFake(t0)
	users := newUserDB()
	counter := loginguard.NewMemoryCounter(clk)
	guard, err := loginguard.New(counter, gcfg, clk)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := session.NewManager(session.NewMemoryBackend(clk), session.DefaultConfig(), clk)
	if err != nil {
		t.Fatal(err)
	}
	e := &env{
		clk: clk, users: users, flow: newFakeFlow(users), mfa: newFakeMFA(), pk: &fakePasskeys{}, oidc: &fakeOIDC{},
		sess: sess, guard: guard, counter: counter, eph: ephemeral.NewMemory(clk), aud: audit.NewMemory(clk),
		chal: &fakeChallenger{valid: "captcha-ok"}, logs: &bytes.Buffer{},
	}
	cfg := DefaultConfig(panelOrigin, key32(1), key32(2))
	cfg.ResponseFloor = 0 // os testes de tempo ligam isso explicitamente
	for _, m := range mutate {
		m(&cfg)
	}
	e.srv, err = New(cfg, Deps{
		Flow: e.flow, Sessions: sess, Users: users, MFA: e.mfa, Passkeys: e.pk, OIDC: e.oidc,
		Guard: guard, Counter: counter, Ephemeral: e.eph, Audit: e.aud, Challenger: e.chal, Clock: clk,
		Log: slog.New(slog.NewTextHandler(e.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	if err != nil {
		t.Fatal(err)
	}
	e.h = e.srv.Handler()
	return e
}

// --- cliente HTTP de teste, com "cookie jar" ---------------------------------------------------

type client struct {
	t       *testing.T
	e       *env
	cookies map[string]*http.Cookie
	csrf    string
	remote  string
}

func (e *env) client(t *testing.T) *client {
	return &client{t: t, e: e, cookies: map[string]*http.Cookie{}, remote: "203.0.113.10:5555"}
}

type reqOpt func(*http.Request)

func withHeader(k, v string) reqOpt { return func(r *http.Request) { r.Header.Set(k, v) } }
func noHeader(k string) reqOpt      { return func(r *http.Request) { r.Header.Del(k) } }

func (c *client) do(method, path string, body any, opts ...reqOpt) *httptest.ResponseRecorder {
	c.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	case []byte:
		rd = bytes.NewReader(b)
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			c.t.Fatal(err)
		}
		rd = bytes.NewReader(raw)
	}
	req := httptest.NewRequestWithContext(ctx, method, path, rd)
	req.RemoteAddr = c.remote
	if rd != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet {
		req.Header.Set("Origin", panelOrigin)
	}
	if c.csrf != "" && method != http.MethodGet {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	for _, ck := range c.cookies {
		req.AddCookie(ck)
	}
	for _, o := range opts {
		o(req)
	}
	rec := httptest.NewRecorder()
	c.e.h.ServeHTTP(rec, req)
	for _, ck := range rec.Result().Cookies() {
		if ck.MaxAge < 0 || ck.Value == "" {
			delete(c.cookies, ck.Name)
		} else {
			c.cookies[ck.Name] = ck
		}
	}
	return rec
}

func (c *client) post(path string, body any, opts ...reqOpt) *httptest.ResponseRecorder {
	return c.do(http.MethodPost, "/bff/auth"+path, body, opts...)
}

func (c *client) get(path string, opts ...reqOpt) *httptest.ResponseRecorder {
	return c.do(http.MethodGet, "/bff/auth"+path, nil, opts...)
}

func (c *client) del(path string, opts ...reqOpt) *httptest.ResponseRecorder {
	return c.do(http.MethodDelete, "/bff/auth"+path, nil, opts...)
}

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if rec.Body.Len() == 0 {
		return nil
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("corpo não é JSON: %q (%v)", rec.Body.String(), err)
	}
	return m
}

func wantStatus(t *testing.T, rec *httptest.ResponseRecorder, status int) {
	t.Helper()
	if rec.Code != status {
		t.Fatalf("status = %d, quer %d; corpo: %s", rec.Code, status, rec.Body.String())
	}
}

func wantCode(t *testing.T, rec *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	wantStatus(t, rec, status)
	if got := decodeBody(t, rec)["code"]; got != code {
		t.Fatalf("code = %v, quer %q", got, code)
	}
}

// login faz um login por senha completo (sem MFA) e guarda o CSRF no cliente.
func (c *client) login(email, pw string) {
	c.t.Helper()
	rec := c.post("/login", map[string]string{"email": email, "password": pw})
	wantStatus(c.t, rec, http.StatusOK)
	body := decodeBody(c.t, rec)
	tok, _ := body["csrf_token"].(string)
	if tok == "" {
		c.t.Fatalf("login sem csrf_token: %v", body)
	}
	c.csrf = tok
}

// reauth libera as ações sensíveis.
func (c *client) reauth(pw string) {
	c.t.Helper()
	wantStatus(c.t, c.post("/reauth", map[string]string{"password": pw}), http.StatusNoContent)
}

func cookieOf(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func queryOf(t *testing.T, rec *httptest.ResponseRecorder) (loc *url.URL) {
	t.Helper()
	u, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("Location inválido: %v", err)
	}
	return u
}

var errBoom = errors.New("falha simulada")

func contextWithTimeout() (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, 5*time.Second)
}

// recorder abrevia o tipo de resposta de teste.
type recorder = httptest.ResponseRecorder
