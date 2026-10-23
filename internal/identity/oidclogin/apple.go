package oidclogin

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/Americo509/alo-api/internal/clock"
)

func encodeB64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

const appleAudience = "https://appleid.apple.com"

// AppleSecret gera o client_secret da Apple: um JWT ES256 curto, assinado com a
// chave privada da conta Apple Developer. Gerado a cada troca de código, com
// validade de poucos minutos — nada de segredo de longa duração em memória. A
// chave fica atrás de crypto.Signer, então pode estar no KMS/HSM e nunca no
// código nem no repositório.
type AppleSecret struct {
	TeamID   string        // iss
	ClientID string        // sub: o Services ID
	KeyID    string        // kid da chave cadastrada na Apple
	Signer   crypto.Signer // chave EC P-256
	Clock    clock.Clock
	// Lifetime do JWT. Padrão 5 min; a Apple aceita até 6 meses.
	Lifetime time.Duration
}

// Secret implementa SecretSource.
func (a AppleSecret) Secret(context.Context) (string, error) {
	if a.TeamID == "" || a.ClientID == "" || a.KeyID == "" || a.Signer == nil || a.Clock == nil {
		return "", errors.New("oidclogin: AppleSecret incompleto")
	}
	life := a.Lifetime
	if life <= 0 {
		life = 5 * time.Minute
	}
	now := a.Clock.Now()
	header, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": a.KeyID, "typ": "JWT"})
	claims, _ := json.Marshal(map[string]any{
		"iss": a.TeamID,
		"iat": now.Unix(),
		"exp": now.Add(life).Unix(),
		"aud": appleAudience,
		"sub": a.ClientID,
	})
	signingInput := encodeB64(header) + "." + encodeB64(claims)
	digest := sha256.Sum256([]byte(signingInput))

	der, err := a.Signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("oidclogin: assinar client_secret da Apple: %w", err)
	}
	raw, err := derToRawES256(der)
	if err != nil {
		return "", err
	}
	return signingInput + "." + encodeB64(raw), nil
}

// derToRawES256 converte a assinatura ECDSA em ASN.1 DER (formato do
// crypto.Signer) para o formato R||S de 64 bytes exigido pelo JWS ES256.
func derToRawES256(der []byte) ([]byte, error) {
	var sig struct{ R, S *big.Int }
	if rest, err := asn1.Unmarshal(der, &sig); err != nil || len(rest) != 0 {
		return nil, errors.New("oidclogin: assinatura ECDSA inválida")
	}
	out := make([]byte, 64)
	if sig.R.BitLen() > 256 || sig.S.BitLen() > 256 {
		return nil, errors.New("oidclogin: assinatura ECDSA fora de P-256")
	}
	sig.R.FillBytes(out[:32])
	sig.S.FillBytes(out[32:])
	return out, nil
}
