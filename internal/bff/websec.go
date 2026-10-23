// Package bff é a camada HTTP entre o painel (SPA) e os serviços de identidade
// (ADR-0009): o navegador guarda só um cookie de sessão HttpOnly e nunca vê um
// token. Este arquivo reúne as proteções que valem para todas as rotas.
package bff

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// ---------------------------------------------------------------------------
// IP do cliente

// IPResolver descobre o IP do cliente SEM acreditar em cabeçalhos forjados:
// X-Forwarded-For só vale quando a conexão vem de um proxy confiável, e o IP do
// cliente é o primeiro endereço NÃO confiável lido da direita para a esquerda
// (o que o proxy confiável de fato viu).
type IPResolver struct {
	trusted []netip.Prefix
}

// NewIPResolver cria o resolvedor. Sem proxies confiáveis, usa só o RemoteAddr.
func NewIPResolver(trusted []netip.Prefix) *IPResolver { return &IPResolver{trusted: trusted} }

func (r *IPResolver) isTrusted(a netip.Addr) bool {
	for _, p := range r.trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// From devolve o IP do cliente (sem porta), ou "" se não for possível.
func (r *IPResolver) From(req *http.Request) string {
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		host = req.RemoteAddr
	}
	remote, err := netip.ParseAddr(host)
	if err != nil {
		return ""
	}
	remote = remote.Unmap()
	if !r.isTrusted(remote) {
		return remote.String()
	}
	parts := strings.Split(strings.Join(req.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(parts) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(parts[i]))
		if err != nil {
			return remote.String() // cabeçalho malformado: não arrisca
		}
		a = a.Unmap()
		if !r.isTrusted(a) {
			return a.String()
		}
	}
	return remote.String()
}

// rateKey normaliza o IP para chave de limite: IPv6 vira o prefixo /64, porque
// quem tem uma rede IPv6 tem 2^64 endereços e contornaria um limite por endereço.
func rateKey(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return "desconhecido"
	}
	a = a.Unmap()
	if a.Is6() {
		p, _ := a.Prefix(64)
		return p.String()
	}
	return a.String()
}

// ---------------------------------------------------------------------------
// Cabeçalhos de segurança

// securityHeaders aplica os cabeçalhos a TODAS as respostas da API.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("Pragma", "no-cache")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=()")
		h.Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

// ---------------------------------------------------------------------------
// Origem e CSRF

func isUnsafe(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return false
	}
	return true
}

// originAllowed confere o cabeçalho Origin de requisições que alteram estado.
// Navegador sempre envia Origin em POST/PUT/PATCH/DELETE; ausência ou valor
// diferente do painel é recusada. Sec-Fetch-Site "cross-site" também.
func (s *Server) originAllowed(r *http.Request) bool {
	if !isUnsafe(r.Method) {
		return true
	}
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}
	_, ok := s.origins[origin]
	return ok
}

// csrfToken deriva o token CSRF da sessão: HMAC(chave do servidor, ID da
// sessão). Sem estado extra, e inútil para quem não tem a chave.
func (s *Server) csrfToken(sessionID string) string {
	m := hmac.New(sha256.New, s.cfg.CSRFKey)
	m.Write([]byte("csrf:" + sessionID))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (s *Server) csrfValid(r *http.Request, sessionID string) bool {
	got := r.Header.Get("X-CSRF-Token")
	if got == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(s.csrfToken(sessionID))) == 1
}

// ---------------------------------------------------------------------------
// JSON

// b64 é a codificação de identificadores binários na API (base64 URL, sem padding).
var b64 = base64.RawURLEncoding

const maxBody = 64 << 10 // 64 KiB: de sobra para qualquer corpo desta API

// limitBody aplica o teto de tamanho do corpo.
func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		next.ServeHTTP(w, r)
	})
}

func isJSON(r *http.Request) bool {
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	return err == nil && mt == "application/json"
}

// decode lê um corpo JSON estrito: tipo application/json, sem campos
// desconhecidos, um único valor. Em caso de erro já responde e devolve false.
func (s *Server) decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	if !isJSON(r) {
		s.problem(w, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return false
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			s.problem(w, http.StatusRequestEntityTooLarge, "payload_too_large")
			return false
		}
		s.problem(w, http.StatusBadRequest, "invalid_json")
		return false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		s.problem(w, http.StatusBadRequest, "invalid_json")
		return false
	}
	return true
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

// títulos legíveis (pt-BR) por código de erro; o SPA usa o `code`.
//
//nolint:gosec // G101: mensagens de erro para o usuário, não credenciais
var titles = map[string]string{
	"invalid_request":        "Requisição inválida.",
	"invalid_json":           "O corpo da requisição não é um JSON válido.",
	"payload_too_large":      "O corpo da requisição é grande demais.",
	"unsupported_media_type": "Use Content-Type: application/json.",
	"forbidden_origin":       "Origem não permitida.",
	"csrf_invalid":           "Token CSRF ausente ou inválido.",
	"unauthenticated":        "É preciso entrar para continuar.",
	"reauth_required":        "Confirme sua identidade para continuar.",
	"invalid_credentials":    "E-mail ou senha incorretos.",
	"invalid_code":           "Código incorreto ou expirado.",
	"mfa_expired":            "A verificação expirou. Entre novamente.",
	"challenge_required":     "Conclua a verificação anti-robô para continuar.",
	"too_many_requests":      "Muitas tentativas. Tente novamente mais tarde.",
	"invalid_token":          "Link inválido ou expirado.",
	"invalid_email":          "E-mail inválido.",
	"password_too_short":     "A senha é curta demais.",
	"password_too_long":      "A senha é longa demais.",
	"password_breached":      "Esta senha apareceu em vazamentos conhecidos. Escolha outra.",
	"account_unavailable":    "Esta conta não pode ser usada.",
	"passkey_failed":         "Não foi possível validar a passkey.",
	"not_found":              "Não encontrado.",
	"conflict":               "Conflito com o estado atual.",
	"unknown_provider":       "Provedor desconhecido.",
	"service_unavailable":    "Serviço temporariamente indisponível.",
	"internal":               "Erro interno.",
}

// problem responde no formato RFC 9457 (application/problem+json).
func (s *Server) problem(w http.ResponseWriter, status int, code string) {
	title := titles[code]
	if title == "" {
		title = http.StatusText(status)
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"type": "about:blank", "title": title, "status": status, "code": code,
	})
}
