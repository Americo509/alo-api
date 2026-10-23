package passkey

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// softAuth é um autenticador WebAuthn de software (chave P-256, ES256, atestado
// "none") para exercitar as cerimônias reais da biblioteca nos testes.
type softAuth struct {
	t          *testing.T
	priv       *ecdsa.PrivateKey
	credID     []byte
	userHandle []byte
	counter    uint32

	// Ajustes para simular autenticadores defeituosos ou ataques.
	origin       string // origem informada no clientData
	userVerified bool
	rpID         string
}

var b64 = base64.RawURLEncoding

func newSoftAuth(t *testing.T, rpID, origin string) *softAuth {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := make([]byte, 32)
	if _, err := rand.Read(id); err != nil {
		t.Fatal(err)
	}
	return &softAuth{t: t, priv: priv, credID: id, origin: origin, userVerified: true, rpID: rpID}
}

// options extrai campos de interesse do JSON de opções devolvido pelo serviço.
func publicKeyOf(t *testing.T, v any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var top map[string]any
	if err := json.Unmarshal(raw, &top); err != nil {
		t.Fatal(err)
	}
	pk, ok := top["publicKey"].(map[string]any)
	if !ok {
		t.Fatalf("opções sem publicKey: %s", raw)
	}
	return pk
}

func (a *softAuth) flags(attested bool) byte {
	f := byte(0x01) // UP: usuário presente
	if a.userVerified {
		f |= 0x04 // UV
	}
	if attested {
		f |= 0x40 // AT: dados de credencial anexados
	}
	return f
}

func (a *softAuth) rpHash() []byte {
	h := sha256.Sum256([]byte(a.rpID))
	return h[:]
}

func (a *softAuth) clientData(typ, challenge string) []byte {
	cd, _ := json.Marshal(map[string]any{
		"type": typ, "challenge": challenge, "origin": a.origin, "crossOrigin": false,
	})
	return cd
}

// register produz o corpo JSON da resposta de registro para as opções dadas.
func (a *softAuth) register(options any) []byte {
	a.t.Helper()
	pk := publicKeyOf(a.t, options)
	challenge, _ := pk["challenge"].(string)
	if user, ok := pk["user"].(map[string]any); ok {
		a.userHandle, _ = b64.DecodeString(user["id"].(string))
	}

	em, err := cbor.CTAP2EncOptions().EncMode()
	if err != nil {
		a.t.Fatal(err)
	}
	pub, err := a.priv.PublicKey.Bytes() // 0x04 || X || Y
	if err != nil {
		a.t.Fatal(err)
	}
	cose, err := em.Marshal(map[int]any{1: 2, 3: -7, -1: 1, -2: pub[1:33], -3: pub[33:65]})
	if err != nil {
		a.t.Fatal(err)
	}

	var auth bytes.Buffer
	auth.Write(a.rpHash())
	auth.WriteByte(a.flags(true))
	_ = binary.Write(&auth, binary.BigEndian, a.counter)
	auth.Write(make([]byte, 16))                                     // AAGUID zerado
	_ = binary.Write(&auth, binary.BigEndian, uint16(len(a.credID))) //nolint:gosec // 32
	auth.Write(a.credID)
	auth.Write(cose)

	att, err := em.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": auth.Bytes()})
	if err != nil {
		a.t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{
		"id": b64.EncodeToString(a.credID), "rawId": b64.EncodeToString(a.credID), "type": "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(a.clientData("webauthn.create", challenge)),
			"attestationObject": b64.EncodeToString(att),
		},
	})
	return body
}

// assert produz o corpo JSON da resposta de login. bump=false repete o contador
// (simula clone ou autenticador sem contador crescente).
func (a *softAuth) assert(options any, counter uint32) []byte {
	a.t.Helper()
	pk := publicKeyOf(a.t, options)
	challenge, _ := pk["challenge"].(string)
	a.counter = counter

	var auth bytes.Buffer
	auth.Write(a.rpHash())
	auth.WriteByte(a.flags(false))
	_ = binary.Write(&auth, binary.BigEndian, a.counter)

	cd := a.clientData("webauthn.get", challenge)
	cdHash := sha256.Sum256(cd)
	digest := sha256.Sum256(append(append([]byte{}, auth.Bytes()...), cdHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, a.priv, digest[:])
	if err != nil {
		a.t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{
		"id": b64.EncodeToString(a.credID), "rawId": b64.EncodeToString(a.credID), "type": "public-key",
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(cd),
			"authenticatorData": b64.EncodeToString(auth.Bytes()),
			"signature":         b64.EncodeToString(sig),
			"userHandle":        b64.EncodeToString(a.userHandle),
		},
	})
	return body
}

func post(t *testing.T, body []byte) *http.Request {
	t.Helper()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	return r
}
