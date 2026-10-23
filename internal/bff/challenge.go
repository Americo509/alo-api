package bff

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Challenger verifica uma prova anti-robô (CAPTCHA/Turnstile). Devolve nil se a
// prova é válida.
type Challenger interface {
	Verify(ctx context.Context, token, ip string) error
}

// ErrChallenge: prova ausente, inválida ou expirada.
var ErrChallenge = errors.New("bff: desafio anti-robô inválido")

// SiteVerify fala o protocolo "siteverify" comum a Cloudflare Turnstile,
// hCaptcha e Google reCAPTCHA: POST com secret, response e remoteip, resposta
// JSON com "success". Trocar de provedor é trocar a URL e o segredo.
type SiteVerify struct {
	url    string
	secret string
	client *http.Client
}

// NewSiteVerify valida a URL (https) e cria o verificador. O segredo vem do
// cofre de segredos e nunca é logado.
func NewSiteVerify(verifyURL, secret string, client *http.Client, allowInsecure bool) (*SiteVerify, error) {
	u, err := url.Parse(verifyURL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && (u.Scheme != "http" || !allowInsecure)) {
		return nil, errors.New("bff: URL do verificador anti-robô deve usar https")
	}
	if strings.TrimSpace(secret) == "" {
		return nil, errors.New("bff: segredo do verificador anti-robô ausente")
	}
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &SiteVerify{url: verifyURL, secret: secret, client: client}, nil
}

const maxChallengeToken = 2048

// Verify implementa Challenger.
func (s *SiteVerify) Verify(ctx context.Context, token, ip string) error {
	if token == "" || len(token) > maxChallengeToken {
		return ErrChallenge
	}
	form := url.Values{"secret": {s.secret}, "response": {token}}
	if ip != "" {
		form.Set("remoteip", ip)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := s.client.Do(req)
	if err != nil {
		// Erro de rede NÃO inclui a URL/segredo; o chamador decide a política.
		return fmt.Errorf("bff: verificador anti-robô indisponível")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bff: verificador anti-robô respondeu %d", resp.StatusCode)
	}
	var out struct {
		Success bool `json:"success"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&out); err != nil {
		return fmt.Errorf("bff: resposta inválida do verificador anti-robô")
	}
	if !out.Success {
		return ErrChallenge
	}
	return nil
}
