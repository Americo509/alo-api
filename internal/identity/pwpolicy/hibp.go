package pwpolicy

import (
	"bufio"
	"context"
	"crypto/sha1" //nolint:gosec // SHA-1 é exigido pela API Pwned Passwords, não é uso de segurança
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// HIBP consulta a API Pwned Passwords com k-anonimato: só os 5 primeiros
// caracteres do SHA-1 da senha saem do servidor; a senha nunca sai. A resposta
// traz os sufixos de todos os hashes com aquele prefixo, e comparamos
// localmente.
type HIBP struct {
	client  *http.Client
	baseURL string
}

const hibpBase = "https://api.pwnedpasswords.com/range/"

// NewHIBP cria o verificador. O client padrão tem timeout de 3s.
func NewHIBP(client *http.Client) *HIBP {
	if client == nil {
		client = &http.Client{Timeout: 3 * time.Second}
	}
	return &HIBP{client: client, baseURL: hibpBase}
}

// TimesSeen implementa BreachChecker.
func (h *HIBP) TimesSeen(ctx context.Context, password string) (int, error) {
	sum := sha1.Sum([]byte(password)) //nolint:gosec // exigido pela API
	full := fmt.Sprintf("%X", sum)
	prefix, suffix := full[:5], full[5:]

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.baseURL+prefix, nil)
	if err != nil {
		return 0, err
	}
	// Add-Padding evita que o tamanho da resposta revele o prefixo consultado.
	req.Header.Set("Add-Padding", "true")
	resp, err := h.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("pwpolicy: HIBP respondeu %d", resp.StatusCode)
	}

	sc := bufio.NewScanner(io.LimitReader(resp.Body, 2<<20))
	for sc.Scan() {
		line := sc.Text()
		suf, count, ok := strings.Cut(line, ":")
		if !ok || !strings.EqualFold(suf, suffix) {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(count))
		if err != nil {
			return 0, fmt.Errorf("pwpolicy: contagem inválida do HIBP: %w", err)
		}
		return n, nil
	}
	if err := sc.Err(); err != nil {
		return 0, err
	}
	return 0, nil
}
