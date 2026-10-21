package session

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSetAndReadCookie(t *testing.T) {
	w := httptest.NewRecorder()
	SetCookie(w, "abc123")
	res := w.Result()
	t.Cleanup(func() { _ = res.Body.Close() })

	c := res.Cookies()[0]
	switch {
	case c.Name != CookieName || c.Value != "abc123":
		t.Fatalf("cookie = %+v", c)
	case !c.Secure || !c.HttpOnly:
		t.Fatal("cookie deve ser Secure e HttpOnly")
	case c.SameSite != http.SameSiteLaxMode:
		t.Fatal("cookie deve ser SameSite=Lax")
	case c.Path != "/" || c.Domain != "":
		t.Fatal("__Host- exige Path=/ e sem Domain")
	}

	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	r.AddCookie(c)
	id, ok := IDFromRequest(r)
	if !ok || id != "abc123" {
		t.Fatalf("IDFromRequest = %q, %t", id, ok)
	}
}

func TestClearCookie(t *testing.T) {
	w := httptest.NewRecorder()
	ClearCookie(w)
	c := w.Result().Cookies()[0]
	if c.MaxAge >= 0 {
		t.Fatalf("ClearCookie deve expirar o cookie, MaxAge=%d", c.MaxAge)
	}
}

func TestNoCookie(t *testing.T) {
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	if _, ok := IDFromRequest(r); ok {
		t.Fatal("sem cookie deveria dar ok=false")
	}
}
