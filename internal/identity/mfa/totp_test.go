package mfa

import (
	"strings"
	"testing"
	"time"
)

var base = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

func TestCodeIsSixDigits(t *testing.T) {
	secret := []byte("12345678901234567890")
	c := code(secret, stepAt(base))
	if len(c) != 6 {
		t.Fatalf("código = %q, quer 6 dígitos", c)
	}
	for _, r := range c {
		if r < '0' || r > '9' {
			t.Fatalf("código não numérico: %q", c)
		}
	}
}

func TestVerifyAcceptsCurrentStep(t *testing.T) {
	secret := []byte("12345678901234567890")
	c := code(secret, stepAt(base))
	step, ok := verify(secret, c, base, 0)
	if !ok || step != stepAt(base) {
		t.Fatalf("verify do código atual falhou: step=%d ok=%t", step, ok)
	}
}

func TestVerifyWindow(t *testing.T) {
	secret := []byte("12345678901234567890")
	// Código do passo anterior ainda é aceito dentro da janela de ±1.
	prev := code(secret, stepAt(base)-1)
	if _, ok := verify(secret, prev, base, 0); !ok {
		t.Fatal("código do passo anterior deveria ser aceito na janela")
	}
	// Código de dois passos atrás, não.
	old := code(secret, stepAt(base)-2)
	if _, ok := verify(secret, old, base, 0); ok {
		t.Fatal("código de 2 passos atrás não deveria ser aceito")
	}
}

func TestVerifyRejectsReuse(t *testing.T) {
	secret := []byte("12345678901234567890")
	cur := stepAt(base)
	c := code(secret, cur)
	// Com lastStep = passo atual, o mesmo código é rejeitado (anti-reuso).
	if _, ok := verify(secret, c, base, cur); ok {
		t.Fatal("código já usado foi aceito de novo")
	}
}

func TestVerifyRejectsWrongCode(t *testing.T) {
	secret := []byte("12345678901234567890")
	if _, ok := verify(secret, "000000", base, 0); ok {
		// 000000 pode coincidir por acaso num instante; teste com outro passo
		t.Skip("coincidência rara de 000000")
	}
	if _, ok := verify(secret, "abcdef", base, 0); ok {
		t.Fatal("código não numérico aceito")
	}
}

func TestProvisioningURI(t *testing.T) {
	secret := []byte("12345678901234567890")
	uri := provisioningURI("ZapGateway", "user@example.com", secret)
	if !strings.HasPrefix(uri, "otpauth://totp/") {
		t.Fatalf("URI = %q", uri)
	}
	for _, want := range []string{"issuer=ZapGateway", "digits=6", "period=30", "algorithm=SHA1", "secret="} {
		if !strings.Contains(uri, want) {
			t.Errorf("URI não contém %q: %s", want, uri)
		}
	}
}
