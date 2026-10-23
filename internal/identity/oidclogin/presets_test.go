package oidclogin

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/Americo509/alo-api/internal/clock"
)

func TestGoogleConfig(t *testing.T) {
	c, err := GoogleConfig("id.apps.googleusercontent.com", StaticSecret("s"), "https://app.exemplo.com.br/bff/auth/oidc/google/callback")
	if err != nil {
		t.Fatal(err)
	}
	if c.Issuer != "https://accounts.google.com" || c.Name != "google" || c.FormPost {
		t.Errorf("config: %+v", c)
	}
	if got := len(c.Scopes); got != 3 || c.Scopes[0] != "openid" {
		t.Errorf("escopos: %v", c.Scopes)
	}
	if _, err := GoogleConfig("", StaticSecret("s"), "x"); err == nil {
		t.Error("client_id vazio aceito")
	}
	if _, err := GoogleConfig("id", nil, "x"); err == nil {
		t.Error("segredo ausente aceito")
	}
}

func TestAppleConfig(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sec := AppleSecret{TeamID: "TEAM", ClientID: "br.com.exemplo.web", KeyID: "KID", Signer: key,
		Clock: clock.NewFake(time.Unix(1_700_000_000, 0))}
	c, err := AppleConfig(sec, "https://app.exemplo.com.br/bff/auth/oidc/apple/callback")
	if err != nil {
		t.Fatal(err)
	}
	if c.Issuer != "https://appleid.apple.com" || !c.FormPost || c.ClientID != "br.com.exemplo.web" || c.Name != "apple" {
		t.Errorf("config: %+v", c)
	}
	if jwt, err := c.Secret.Secret(ctx); err != nil || jwt == "" {
		t.Errorf("segredo da Apple: %q %v", jwt, err)
	}
	sec.KeyID = ""
	if _, err := AppleConfig(sec, "x"); err == nil {
		t.Error("config incompleta aceita")
	}
}
