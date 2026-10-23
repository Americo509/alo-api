package oidclogin

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// fakeIdP é um provedor OIDC mínimo: descoberta, JWKS e endpoint de token. O
// endpoint de token VALIDA o PKCE (S256) de verdade, então o fluxo só funciona
// se o serviço enviar o code_verifier correto.
type fakeIdP struct {
	t   *testing.T
	srv *httptest.Server
	key *rsa.PrivateKey
	kid string
	now time.Time

	mu    sync.Mutex
	codes map[string]issued
	// secretSeen registra o client_secret recebido na última troca.
	secretSeen string
}

type issued struct {
	challenge string
	nonce     string
	clientID  string
	redirect  string
	claims    map[string]any
	opts      tokenOpts
}

// tokenOpts distorce o id_token para simular ataques.
type tokenOpts struct {
	signWith *rsa.PrivateKey // chave diferente da publicada no JWKS
	nonce    *string         // nonce diferente do pedido
	aud      string
	iss      string
	exp      time.Time
}

func newFakeIdP(t *testing.T, now time.Time) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIdP{t: t, key: key, kid: "k1", now: now, codes: map[string]issued{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", f.discovery)
	mux.HandleFunc("GET /keys", f.jwks)
	mux.HandleFunc("POST /token", f.token)
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIdP) URL() string { return f.srv.URL }

func (f *fakeIdP) discovery(w http.ResponseWriter, _ *http.Request) {
	_ = json.NewEncoder(w).Encode(map[string]any{
		"issuer":                                f.srv.URL,
		"authorization_endpoint":                f.srv.URL + "/authorize",
		"token_endpoint":                        f.srv.URL + "/token",
		"jwks_uri":                              f.srv.URL + "/keys",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

func (f *fakeIdP) jwks(w http.ResponseWriter, _ *http.Request) {
	_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: &f.key.PublicKey, KeyID: f.kid, Algorithm: "RS256", Use: "sig"},
	}})
}

// issueCode simula o usuário aprovando no provedor: lê os parâmetros da URL de
// autorização e devolve o code e o state que o provedor mandaria ao callback.
func (f *fakeIdP) issueCode(authURL string, claims map[string]any, opts tokenOpts) (code, state string) {
	f.t.Helper()
	u, err := url.Parse(authURL)
	if err != nil {
		f.t.Fatal(err)
	}
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		f.t.Fatalf("a URL de autorização não usa PKCE S256: %s", authURL)
	}
	if q.Get("response_type") != "code" {
		f.t.Fatalf("response_type = %q, quer code", q.Get("response_type"))
	}
	if q.Get("client_secret") != "" {
		f.t.Fatal("client_secret vazou na URL de autorização")
	}
	buf := make([]byte, 16)
	_, _ = rand.Read(buf)
	code = base64.RawURLEncoding.EncodeToString(buf)
	f.mu.Lock()
	f.codes[code] = issued{
		challenge: q.Get("code_challenge"), nonce: q.Get("nonce"),
		clientID: q.Get("client_id"), redirect: q.Get("redirect_uri"),
		claims: claims, opts: opts,
	}
	f.mu.Unlock()
	return code, q.Get("state")
}

func (f *fakeIdP) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	is, ok := f.codes[r.PostForm.Get("code")]
	delete(f.codes, r.PostForm.Get("code")) // código de uso único
	f.secretSeen = r.PostForm.Get("client_secret")
	f.mu.Unlock()

	fail := func(msg string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant", "error_description": msg})
	}
	switch {
	case !ok:
		fail("código desconhecido ou já usado")
		return
	case r.PostForm.Get("grant_type") != "authorization_code":
		fail("grant_type")
		return
	case r.PostForm.Get("client_id") != is.clientID || r.PostForm.Get("redirect_uri") != is.redirect:
		fail("client_id ou redirect_uri não conferem")
		return
	}
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != is.challenge {
		fail("PKCE: code_verifier não confere com o code_challenge")
		return
	}

	nonce := is.nonce
	if is.opts.nonce != nil {
		nonce = *is.opts.nonce
	}
	aud, iss, exp := is.clientID, f.srv.URL, f.now.Add(time.Hour)
	if is.opts.aud != "" {
		aud = is.opts.aud
	}
	if is.opts.iss != "" {
		iss = is.opts.iss
	}
	if !is.opts.exp.IsZero() {
		exp = is.opts.exp
	}
	claims := map[string]any{
		"iss": iss, "aud": aud, "iat": f.now.Unix(), "exp": exp.Unix(), "nonce": nonce,
	}
	for k, v := range is.claims {
		claims[k] = v
	}
	signKey := f.key
	if is.opts.signWith != nil {
		signKey = is.opts.signWith
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: signKey, KeyID: f.kid}},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	raw, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": "at-" + r.PostForm.Get("code"), "token_type": "Bearer", "id_token": raw,
	})
}
