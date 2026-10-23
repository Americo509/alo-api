//go:build integration

package mfa

import (
	"net/url"
	"time"
)

// CodeForEnrollURI calcula o TOTP válido num instante a partir da otpauth URI
// devolvida por BeginEnroll. Exposto só na build de integração, para os testes
// externos (package mfa_test) exercitarem os fluxos sem duplicar o cálculo.
func CodeForEnrollURI(uri string, now time.Time) (string, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return "", err
	}
	secret, err := b32.DecodeString(u.Query().Get("secret"))
	if err != nil {
		return "", err
	}
	return code(secret, stepAt(now)), nil
}
