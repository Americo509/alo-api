package envelope_test

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"testing"

	"github.com/Americo509/alo-api/internal/crypto/envelope"
	"github.com/Americo509/alo-api/internal/crypto/envelope/envelopetest"
)

var (
	ctx       = context.Background()
	aadA      = []byte("instance:0b5e7c1a/field:noise_key")
	aadB      = []byte("instance:9f00aa21/field:noise_key")
	plaintext = []byte("estado de sessão de teste — sem valor real")
)

func newKey(t *testing.T) (*envelope.Service, *envelopetest.LocalKeyManager, *envelope.DataKey, envelope.WrappedKey) {
	t.Helper()
	km := envelopetest.New()
	svc := envelope.New(km)
	dk, w, err := svc.GenerateKey(ctx)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return svc, km, dk, w
}

func TestSealOpenRoundTrip(t *testing.T) {
	_, _, dk, _ := newKey(t)
	sealed, err := dk.Seal(plaintext, aadA)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if bytes.Contains(sealed, plaintext) {
		t.Fatal("texto em claro aparece no blob cifrado")
	}
	got, err := dk.Open(sealed, aadA)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("Open devolveu %q", got)
	}
}

func TestSealIsRandomized(t *testing.T) {
	_, _, dk, _ := newKey(t)
	a, _ := dk.Seal(plaintext, aadA)
	b, _ := dk.Seal(plaintext, aadA)
	if bytes.Equal(a, b) {
		t.Fatal("duas cifragens do mesmo texto deram o mesmo blob (nonce repetido?)")
	}
}

func TestOpenRejectsTampering(t *testing.T) {
	_, _, dk, _ := newKey(t)
	sealed, _ := dk.Seal(plaintext, aadA)

	cases := map[string]func([]byte) []byte{
		"byte do ciphertext": func(b []byte) []byte { b[len(b)-1] ^= 0x01; return b },
		"byte do nonce":      func(b []byte) []byte { b[1] ^= 0x01; return b },
		"versão de formato":  func(b []byte) []byte { b[0] = 0x02; return b },
		"truncado":           func(b []byte) []byte { return b[:len(b)-1] },
		"curto demais":       func(b []byte) []byte { return b[:5] },
		"vazio":              func([]byte) []byte { return nil },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			blob := mutate(bytes.Clone(sealed))
			if _, err := dk.Open(blob, aadA); !errors.Is(err, envelope.ErrOpen) {
				t.Fatalf("esperava ErrOpen, veio %v", err)
			}
		})
	}
}

func TestOpenRejectsBlobFromAnotherInstance(t *testing.T) {
	_, _, dk, _ := newKey(t)
	sealed, _ := dk.Seal(plaintext, aadA)
	if _, err := dk.Open(sealed, aadB); !errors.Is(err, envelope.ErrOpen) {
		t.Fatalf("blob aberto com AAD de outra instância: err=%v", err)
	}
}

func TestOpenRejectsOtherKey(t *testing.T) {
	_, _, dk1, _ := newKey(t)
	_, _, dk2, _ := newKey(t)
	sealed, _ := dk1.Seal(plaintext, aadA)
	if _, err := dk2.Open(sealed, aadA); !errors.Is(err, envelope.ErrOpen) {
		t.Fatalf("blob aberto com chave de outra instância: err=%v", err)
	}
}

func TestWrappedKeyReopensSameKey(t *testing.T) {
	svc, _, dk, w := newKey(t)
	sealed, _ := dk.Seal(plaintext, aadA)

	reopened, err := svc.OpenKey(ctx, w)
	if err != nil {
		t.Fatalf("OpenKey: %v", err)
	}
	if got, err := reopened.Open(sealed, aadA); err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("chave reaberta não abre o blob: %v", err)
	}
}

func TestMasterKeyRotationAndRewrap(t *testing.T) {
	svc, km, dk, w := newKey(t)
	sealed, _ := dk.Seal(plaintext, aadA)

	km.Rotate()
	rewrapped, err := svc.Rewrap(ctx, w)
	if err != nil {
		t.Fatalf("Rewrap: %v", err)
	}
	if rewrapped.MasterKeyRef == w.MasterKeyRef {
		t.Fatalf("Rewrap não mudou a versão da chave mestra: %s", rewrapped.MasterKeyRef)
	}
	// A DEK continua a mesma: dados antigos abrem sem recifrar o estado.
	reopened, err := svc.OpenKey(ctx, rewrapped)
	if err != nil {
		t.Fatalf("OpenKey após rewrap: %v", err)
	}
	if got, err := reopened.Open(sealed, aadA); err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("dado antigo não abre após rotação: %v", err)
	}
	// A versão antiga continua decifrável até ser aposentada no KMS.
	if _, err := svc.OpenKey(ctx, w); err != nil {
		t.Fatalf("versão antiga deixou de abrir antes da aposentadoria: %v", err)
	}
}

func TestDestroyBlocksUse(t *testing.T) {
	_, _, dk, _ := newKey(t)
	sealed, _ := dk.Seal(plaintext, aadA)
	dk.Destroy()
	if _, err := dk.Seal(plaintext, aadA); !errors.Is(err, envelope.ErrDestroyed) {
		t.Fatalf("Seal após Destroy: %v", err)
	}
	if _, err := dk.Open(sealed, aadA); !errors.Is(err, envelope.ErrDestroyed) {
		t.Fatalf("Open após Destroy: %v", err)
	}
}

func TestKeyManagerFailuresPropagate(t *testing.T) {
	km := envelopetest.New()
	svc := envelope.New(km)
	kmsDown := errors.New("kms indisponível")

	km.FailNext = kmsDown
	if _, _, err := svc.GenerateKey(ctx); !errors.Is(err, kmsDown) {
		t.Fatalf("GenerateKey: esperava erro do KMS, veio %v", err)
	}

	_, w, err := svc.GenerateKey(ctx)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	km.FailNext = kmsDown
	if _, err := svc.OpenKey(ctx, w); !errors.Is(err, kmsDown) {
		t.Fatalf("OpenKey: esperava erro do KMS, veio %v", err)
	}
}

func TestOpenKeyRejectsWrongSize(t *testing.T) {
	km := envelopetest.New()
	short, err := km.Wrap(ctx, []byte("curta"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := envelope.New(km).OpenKey(ctx, short); err == nil {
		t.Fatal("OpenKey aceitou chave com tamanho errado")
	}
}

func TestRandFailureSurfaces(t *testing.T) {
	svc := envelope.New(envelopetest.New(), envelope.WithRand(bytes.NewReader(nil)))
	if _, _, err := svc.GenerateKey(ctx); err == nil {
		t.Fatal("GenerateKey ignorou falha da fonte aleatória")
	}
}

func TestBlindIndex(t *testing.T) {
	svc, _, dk, w := newKey(t)
	phone := []byte("5511900000000")

	a, err := dk.BlindIndex("signal-user", phone)
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 32 || bytes.Contains(a, phone) {
		t.Fatalf("índice inesperado: %x", a)
	}
	b, _ := dk.BlindIndex("signal-user", phone)
	if !bytes.Equal(a, b) {
		t.Fatal("índice não é determinístico")
	}
	// Mesma chave reaberta do banco gera o mesmo índice (buscas continuam valendo).
	reopened, _ := svc.OpenKey(ctx, w)
	if c, _ := reopened.BlindIndex("signal-user", phone); !bytes.Equal(a, c) {
		t.Fatal("índice mudou após reabrir a chave")
	}
	// Domínios diferentes não colidem.
	if d, _ := dk.BlindIndex("chat", phone); bytes.Equal(a, d) {
		t.Fatal("domínios diferentes geraram o mesmo índice")
	}
	// Fronteira domínio/valor sem ambiguidade: ("ab","c") != ("a","bc").
	x, _ := dk.BlindIndex("ab", []byte("c"))
	y, _ := dk.BlindIndex("a", []byte("bc"))
	if bytes.Equal(x, y) {
		t.Fatal("concatenação ambígua entre domínio e valor")
	}
	// Outra instância (outra DEK) gera outro índice: não dá para cruzar bases.
	_, _, other, _ := newKey(t)
	if e, _ := other.BlindIndex("signal-user", phone); bytes.Equal(a, e) {
		t.Fatal("instâncias diferentes geraram o mesmo índice")
	}
	dk.Destroy()
	if _, err := dk.BlindIndex("signal-user", phone); !errors.Is(err, envelope.ErrDestroyed) {
		t.Fatalf("BlindIndex após Destroy: %v", err)
	}
}

// A DEK nunca é usada direto como chave AES (NIST SP 800-57: uma chave por
// propósito): um AES-GCM com a DEK crua não abre o que a DataKey cifrou.
func TestDEKIsNotUsedDirectly(t *testing.T) {
	km := envelopetest.New()
	svc := envelope.New(km)
	dk, w, _ := svc.GenerateKey(ctx)
	sealed, _ := dk.Seal(plaintext, aadA)

	raw, err := km.Unwrap(ctx, w)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(raw)
	gcm, _ := cipher.NewGCM(block)
	if _, err := gcm.Open(nil, sealed[1:13], sealed[13:], append([]byte{1}, aadA...)); err == nil {
		t.Fatal("a DEK crua abriu o blob: subchave não está sendo derivada")
	}
}
