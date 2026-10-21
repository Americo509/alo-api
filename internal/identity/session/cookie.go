package session

import (
	"net/http"
	"time"
)

// CookieName usa o prefixo __Host-: o navegador só aceita se vier com Secure,
// Path=/ e sem Domain, o que impede fixação por subdomínio (ADR-0007, item 7).
const CookieName = "__Host-session"

// SetCookie grava o cookie de sessão na resposta. É um cookie de sessão de
// navegador (sem Max-Age): a expiração de verdade é no servidor. HttpOnly
// impede leitura por JavaScript (defesa contra XSS); SameSite=Lax reduz CSRF.
func SetCookie(w http.ResponseWriter, id string) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    id,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearCookie remove o cookie (logout).
func ClearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}

// IDFromRequest lê o ID da sessão do cookie. ok=false se não houver cookie.
func IDFromRequest(r *http.Request) (id string, ok bool) {
	c, err := r.Cookie(CookieName)
	if err != nil || c.Value == "" {
		return "", false
	}
	return c.Value, true
}
