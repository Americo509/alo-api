// Package mfa implementa o segundo fator do painel (ADR-0007, item 5): TOTP
// (RFC 6238) com segredo cifrado e proteção contra reuso, e códigos de
// recuperação de uso único. Passkeys/WebAuthn ficam em arquivo próprio.
package mfa

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // TOTP (RFC 6238/4226) é definido sobre HMAC-SHA1
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	totpDigits    = 6
	totpPeriod    = 30 * time.Second
	totpSecretLen = 20 // 160 bits, recomendado pela RFC 4226
	// window: quantos passos antes/depois do atual são aceitos, para tolerar
	// relógios ligeiramente dessincronizados (±1 = ±30s).
	totpWindow = 1
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// stepAt devolve o número do passo de tempo para um instante.
func stepAt(t time.Time) int64 { return t.Unix() / int64(totpPeriod.Seconds()) }

// code calcula o TOTP de um passo (RFC 6238 + truncação dinâmica da RFC 4226).
func code(secret []byte, step int64) string {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(step)) //nolint:gosec // step >= 0
	mac := hmac.New(sha1.New, secret)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	v := (uint32(sum[offset]&0x7f) << 24) | (uint32(sum[offset+1]) << 16) |
		(uint32(sum[offset+2]) << 8) | uint32(sum[offset+3])
	return fmt.Sprintf("%0*d", totpDigits, v%pow10(totpDigits))
}

func pow10(n int) uint32 {
	r := uint32(1)
	for range n {
		r *= 10
	}
	return r
}

// verify confere um código contra o segredo na janela em torno de `now`,
// exigindo que o passo aceito seja maior que lastStep (anti-reuso). Devolve o
// passo aceito (para o chamador persistir como novo lastStep).
func verify(secret []byte, input string, now time.Time, lastStep int64) (okStep int64, ok bool) {
	input = strings.TrimSpace(input)
	cur := stepAt(now)
	for off := int64(-totpWindow); off <= totpWindow; off++ {
		step := cur + off
		if step <= lastStep {
			continue // já usado ou anterior ao último aceito
		}
		if subtle.ConstantTimeCompare([]byte(code(secret, step)), []byte(input)) == 1 {
			return step, true
		}
	}
	return 0, false
}

// provisioningURI monta a otpauth:// URI para o app autenticador / QR.
func provisioningURI(issuer, account string, secret []byte) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", b32.EncodeToString(secret))
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprintf("%d", totpDigits))
	q.Set("period", fmt.Sprintf("%d", int(totpPeriod.Seconds())))
	return "otpauth://totp/" + label + "?" + q.Encode()
}
