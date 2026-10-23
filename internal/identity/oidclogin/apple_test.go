package oidclogin

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/Americo509/alo-api/internal/clock"
)

func newAppleSecret(t *testing.T) (AppleSecret, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return AppleSecret{
		TeamID: "TEAM123456", ClientID: "com.exemplo.alo.web", KeyID: "KEYID12345",
		Signer: key, Clock: clock.NewFake(t0),
	}, key
}

// O client_secret da Apple é um JWT ES256 válido, com os campos que a Apple exige,
// verificável com a chave pública (formato R||S, não DER).
func TestAppleClientSecretIsValidES256JWT(t *testing.T) {
	a, key := newAppleSecret(t)
	raw, err := a.Secret(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatalf("JWT malformado: %v", err)
	}
	if kid := tok.Headers[0].KeyID; kid != "KEYID12345" {
		t.Errorf("kid = %q", kid)
	}
	var c jwt.Claims
	if err := tok.Claims(&key.PublicKey, &c); err != nil {
		t.Fatalf("assinatura não verifica com a chave pública: %v", err)
	}
	if c.Issuer != "TEAM123456" || c.Subject != "com.exemplo.alo.web" {
		t.Errorf("iss/sub = %q/%q", c.Issuer, c.Subject)
	}
	if len(c.Audience) != 1 || c.Audience[0] != "https://appleid.apple.com" {
		t.Errorf("aud = %v", c.Audience)
	}
	if got := c.Expiry.Time().Sub(c.IssuedAt.Time()); got != 5*time.Minute {
		t.Errorf("validade = %v, quer 5 min (curta)", got)
	}
}

func TestAppleSecretIsFreshEachTime(t *testing.T) {
	a, _ := newAppleSecret(t)
	s1, _ := a.Secret(ctx)
	s2, _ := a.Secret(ctx)
	if s1 == s2 {
		t.Fatal("ECDSA é randomizado; dois segredos idênticos indicam nonce reutilizado")
	}
}

func TestAppleSecretValidation(t *testing.T) {
	a, _ := newAppleSecret(t)
	for name, mutate := range map[string]func(*AppleSecret){
		"sem team":    func(x *AppleSecret) { x.TeamID = "" },
		"sem client":  func(x *AppleSecret) { x.ClientID = "" },
		"sem kid":     func(x *AppleSecret) { x.KeyID = "" },
		"sem chave":   func(x *AppleSecret) { x.Signer = nil },
		"sem relógio": func(x *AppleSecret) { x.Clock = nil },
	} {
		b := a
		mutate(&b)
		if _, err := b.Secret(ctx); err == nil {
			t.Errorf("%s: configuração inválida aceita", name)
		}
	}
}
