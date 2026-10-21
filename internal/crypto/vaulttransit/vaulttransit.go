// Package vaulttransit implementa envelope.KeyManager sobre o motor Transit do
// HashiCorp Vault. A chave mestra nunca sai do Vault: a aplicação só envia a
// DEK para ser cifrada/decifrada.
//
// Permissões mínimas da política do Vault para a aplicação:
//
//	path "<mount>/encrypt/<key>" { capabilities = ["update"] }
//	path "<mount>/decrypt/<key>" { capabilities = ["update"] }
//	path "<mount>/rewrap/<key>"  { capabilities = ["update"] }
//
// Criar e rotacionar a chave é tarefa de operação, fora da aplicação.
package vaulttransit

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/zapgateway/zap-gateway/internal/crypto/envelope"
)

const maxResponseBytes = 1 << 20

// TokenSource fornece o token do Vault. Em produção, um método de
// autenticação com renovação (AppRole, Kubernetes); StaticToken só para dev.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// StaticToken é um token fixo. Uso restrito a desenvolvimento e testes.
type StaticToken string

func (t StaticToken) Token(context.Context) (string, error) { return string(t), nil }

// Config configura o cliente.
type Config struct {
	Addr    string // ex.: https://vault.interno:8200
	Mount   string // padrão "transit"
	KeyName string // nome da chave mestra
	Token   TokenSource
	// HTTPClient opcional. O padrão tem timeout de 10s.
	HTTPClient *http.Client
	// AllowInsecureHTTP permite http:// (só ambiente local). Sem isso, só https.
	AllowInsecureHTTP bool
}

// Client é o KeyManager do Vault Transit.
type Client struct {
	base  *url.URL
	mount string
	key   string
	ref   string
	token TokenSource
	http  *http.Client
}

var _ envelope.KeyManager = (*Client)(nil)

// ErrWrongKey indica uma WrappedKey cifrada por outra chave mestra.
var ErrWrongKey = errors.New("vaulttransit: chave cifrada por outra chave mestra")

// New valida a configuração e cria o cliente.
func New(cfg Config) (*Client, error) {
	u, err := url.Parse(cfg.Addr)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("vaulttransit: endereço inválido %q", cfg.Addr)
	}
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && cfg.AllowInsecureHTTP:
	default:
		return nil, fmt.Errorf("vaulttransit: esquema %q não permitido (use https)", u.Scheme)
	}
	if cfg.KeyName == "" || strings.ContainsAny(cfg.KeyName, "/?#") {
		return nil, fmt.Errorf("vaulttransit: nome de chave inválido %q", cfg.KeyName)
	}
	if cfg.Token == nil {
		return nil, errors.New("vaulttransit: TokenSource obrigatório")
	}
	mount := strings.Trim(cfg.Mount, "/")
	if mount == "" {
		mount = "transit"
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	return &Client{
		base:  u,
		mount: mount,
		key:   cfg.KeyName,
		ref:   "vault-transit:" + mount + "/" + cfg.KeyName,
		token: cfg.Token,
		http:  hc,
	}, nil
}

// MasterKeyRef devolve o identificador gravado junto de cada WrappedKey.
func (c *Client) MasterKeyRef() string { return c.ref }

func (c *Client) Wrap(ctx context.Context, pt []byte) (envelope.WrappedKey, error) {
	var out struct {
		Data struct {
			Ciphertext string `json:"ciphertext"`
		} `json:"data"`
	}
	in := map[string]string{"plaintext": base64.StdEncoding.EncodeToString(pt)}
	if err := c.call(ctx, "encrypt", in, &out); err != nil {
		return envelope.WrappedKey{}, err
	}
	if !strings.HasPrefix(out.Data.Ciphertext, "vault:v") {
		return envelope.WrappedKey{}, errors.New("vaulttransit: resposta de encrypt sem ciphertext")
	}
	return envelope.WrappedKey{MasterKeyRef: c.ref, Ciphertext: []byte(out.Data.Ciphertext)}, nil
}

func (c *Client) Unwrap(ctx context.Context, w envelope.WrappedKey) ([]byte, error) {
	if w.MasterKeyRef != c.ref {
		return nil, fmt.Errorf("%w: %q", ErrWrongKey, w.MasterKeyRef)
	}
	var out struct {
		Data struct {
			Plaintext string `json:"plaintext"`
		} `json:"data"`
	}
	if err := c.call(ctx, "decrypt", map[string]string{"ciphertext": string(w.Ciphertext)}, &out); err != nil {
		return nil, err
	}
	pt, err := base64.StdEncoding.DecodeString(out.Data.Plaintext)
	if err != nil {
		return nil, errors.New("vaulttransit: plaintext da resposta não é base64")
	}
	return pt, nil
}

func (c *Client) Rewrap(ctx context.Context, w envelope.WrappedKey) (envelope.WrappedKey, error) {
	if w.MasterKeyRef != c.ref {
		return envelope.WrappedKey{}, fmt.Errorf("%w: %q", ErrWrongKey, w.MasterKeyRef)
	}
	var out struct {
		Data struct {
			Ciphertext string `json:"ciphertext"`
		} `json:"data"`
	}
	if err := c.call(ctx, "rewrap", map[string]string{"ciphertext": string(w.Ciphertext)}, &out); err != nil {
		return envelope.WrappedKey{}, err
	}
	return envelope.WrappedKey{MasterKeyRef: c.ref, Ciphertext: []byte(out.Data.Ciphertext)}, nil
}

// call faz POST em /v1/<mount>/<op>/<key>. Erros nunca incluem o corpo da
// requisição (que contém a DEK).
func (c *Client) call(ctx context.Context, op string, in, out any) error {
	tok, err := c.token.Token(ctx)
	if err != nil {
		return fmt.Errorf("vaulttransit: obter token: %w", err)
	}
	body, err := json.Marshal(in)
	if err != nil {
		return fmt.Errorf("vaulttransit: serializar %s: %w", op, err)
	}
	u := c.base.JoinPath("v1", c.mount, op, c.key)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("vaulttransit: montar %s: %w", op, err)
	}
	req.Header.Set("X-Vault-Token", tok)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("vaulttransit: %s: %w", op, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("vaulttransit: ler resposta de %s: %w", op, err)
	}
	if resp.StatusCode/100 != 2 {
		var e struct {
			Errors []string `json:"errors"`
		}
		_ = json.Unmarshal(raw, &e)
		return &StatusError{Op: op, Code: resp.StatusCode, Messages: e.Errors}
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("vaulttransit: resposta de %s inválida: %w", op, err)
	}
	return nil
}

// StatusError é uma resposta de erro do Vault.
type StatusError struct {
	Op       string
	Code     int
	Messages []string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("vaulttransit: %s respondeu %d: %s", e.Op, e.Code, strings.Join(e.Messages, "; "))
}
