package vaulttransit

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/Americo509/alo-api/internal/crypto/envelope"
)

const testToken = "token-de-teste"

// fakeTransit imita o Transit: "cifra" prefixando e invertendo bytes. O que
// importa aqui é o protocolo HTTP, não a criptografia.
func fakeTransit(t *testing.T, version *int, status int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("método %s", r.Method)
		}
		if r.Header.Get("X-Vault-Token") != testToken {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"errors":["permission denied"]}`))
			return
		}
		if status != 0 {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"errors":["falha simulada"]}`))
			return
		}
		var in map[string]string
		_ = json.NewDecoder(r.Body).Decode(&in)
		v := "vault:v" + strconv.Itoa(*version) + ":"
		switch r.URL.Path {
		case "/v1/transit/encrypt/sessions":
			pt, _ := base64.StdEncoding.DecodeString(in["plaintext"])
			writeData(w, "ciphertext", v+base64.StdEncoding.EncodeToString(reverse(pt)))
		case "/v1/transit/decrypt/sessions":
			_, b64, _ := strings.Cut(strings.TrimPrefix(in["ciphertext"], "vault:"), ":")
			ct, _ := base64.StdEncoding.DecodeString(b64)
			writeData(w, "plaintext", base64.StdEncoding.EncodeToString(reverse(ct)))
		case "/v1/transit/rewrap/sessions":
			_, b64, _ := strings.Cut(strings.TrimPrefix(in["ciphertext"], "vault:"), ":")
			writeData(w, "ciphertext", v+b64)
		default:
			t.Errorf("caminho inesperado %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func writeData(w http.ResponseWriter, k, v string) {
	_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{k: v}})
}

func reverse(b []byte) []byte {
	out := bytes.Clone(b)
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func newClient(t *testing.T, addr string, tok TokenSource) *Client {
	t.Helper()
	c, err := New(Config{Addr: addr, KeyName: "sessions", Token: tok, AllowInsecureHTTP: true})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestWrapUnwrapRewrap(t *testing.T) {
	version := 1
	srv := fakeTransit(t, &version, 0)
	defer srv.Close()
	c := newClient(t, srv.URL, StaticToken(testToken))
	ctx := context.Background()
	dek := []byte("0123456789abcdef0123456789abcdef")

	w, err := c.Wrap(ctx, dek)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if w.MasterKeyRef != "vault-transit:transit/sessions" || !bytes.HasPrefix(w.Ciphertext, []byte("vault:v1:")) {
		t.Fatalf("WrappedKey = %+v", w)
	}
	got, err := c.Unwrap(ctx, w)
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("Unwrap = %q, %v", got, err)
	}

	version = 2
	rw, err := c.Rewrap(ctx, w)
	if err != nil || !bytes.HasPrefix(rw.Ciphertext, []byte("vault:v2:")) {
		t.Fatalf("Rewrap = %q, %v", rw.Ciphertext, err)
	}
}

func TestWorksAsEnvelopeKeyManager(t *testing.T) {
	version := 1
	srv := fakeTransit(t, &version, 0)
	defer srv.Close()
	svc := envelope.New(newClient(t, srv.URL, StaticToken(testToken)))
	ctx := context.Background()

	dk, w, err := svc.GenerateKey(ctx)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	sealed, _ := dk.Seal([]byte("x"), []byte("aad"))
	dk2, err := svc.OpenKey(ctx, w)
	if err != nil {
		t.Fatalf("OpenKey: %v", err)
	}
	if _, err := dk2.Open(sealed, []byte("aad")); err != nil {
		t.Fatalf("Open: %v", err)
	}
}

func TestErrorDoesNotLeakKey(t *testing.T) {
	version := 1
	srv := fakeTransit(t, &version, http.StatusInternalServerError)
	defer srv.Close()
	c := newClient(t, srv.URL, StaticToken(testToken))
	dek := []byte("SEGREDO-NAO-PODE-VAZAR-0123456789")

	_, err := c.Wrap(context.Background(), dek)
	var se *StatusError
	if !errors.As(err, &se) || se.Code != http.StatusInternalServerError {
		t.Fatalf("esperava StatusError 500, veio %v", err)
	}
	if strings.Contains(err.Error(), string(dek)) || strings.Contains(err.Error(), base64.StdEncoding.EncodeToString(dek)) {
		t.Fatal("mensagem de erro contém a chave")
	}
}

func TestPermissionDenied(t *testing.T) {
	version := 1
	srv := fakeTransit(t, &version, 0)
	defer srv.Close()
	c := newClient(t, srv.URL, StaticToken("token-errado"))
	var se *StatusError
	if _, err := c.Wrap(context.Background(), []byte("k")); !errors.As(err, &se) || se.Code != http.StatusForbidden {
		t.Fatalf("esperava 403, veio %v", err)
	}
}

func TestUnwrapRejectsForeignKeyRef(t *testing.T) {
	c := newClient(t, "http://127.0.0.1:1", StaticToken(testToken))
	_, err := c.Unwrap(context.Background(), envelope.WrappedKey{MasterKeyRef: "vault-transit:transit/outra", Ciphertext: []byte("vault:v1:x")})
	if !errors.Is(err, ErrWrongKey) {
		t.Fatalf("esperava ErrWrongKey, veio %v", err)
	}
}

func TestConfigValidation(t *testing.T) {
	tok := StaticToken(testToken)
	cases := map[string]Config{
		"http sem permissão": {Addr: "http://vault:8200", KeyName: "k", Token: tok},
		"esquema estranho":   {Addr: "ftp://vault", KeyName: "k", Token: tok},
		"sem host":           {Addr: "https://", KeyName: "k", Token: tok},
		"chave vazia":        {Addr: "https://vault", Token: tok},
		"chave com barra":    {Addr: "https://vault", KeyName: "a/b", Token: tok},
		"sem token":          {Addr: "https://vault", KeyName: "k"},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := New(cfg); err == nil {
				t.Fatal("configuração inválida aceita")
			}
		})
	}
	if _, err := New(Config{Addr: "https://vault:8200", KeyName: "k", Token: tok}); err != nil {
		t.Fatalf("configuração válida recusada: %v", err)
	}
}
