package password

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// fast deixa os testes rápidos sem perder a cobertura do formato e da lógica.
func fast() Option {
	return WithParams(Params{Memory: 8 * 1024, Time: 1, Parallelism: 1, SaltLen: 16, KeyLen: 32})
}

func mustHasher(t *testing.T, p Pepper, opts ...Option) *Hasher {
	t.Helper()
	h, err := NewHasher(p, append([]Option{fast()}, opts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func pepper(t *testing.T, current uint16, versions ...uint16) *HMACPepper {
	t.Helper()
	keys := map[uint16][]byte{}
	for _, v := range versions {
		k := bytes.Repeat([]byte{byte(v & 0xff)}, 32) //nolint:gosec // v pequeno, teste
		keys[v] = k
	}
	p, err := NewHMACPepper(current, keys)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestHashVerifyRoundTrip(t *testing.T) {
	h := mustHasher(t, pepper(t, 1, 1))
	hash, err := h.Hash([]byte("senha-correta-123"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$") {
		t.Fatalf("formato PHC inesperado: %s", hash)
	}
	ok, rehash, err := h.Verify([]byte("senha-correta-123"), hash)
	if err != nil || !ok {
		t.Fatalf("senha correta recusada: ok=%t err=%v", ok, err)
	}
	if rehash {
		t.Error("rehash pedido sem necessidade")
	}
	ok, _, err = h.Verify([]byte("senha-errada"), hash)
	if err != nil || ok {
		t.Fatalf("senha errada aceita: ok=%t err=%v", ok, err)
	}
}

func TestHashIsSalted(t *testing.T) {
	h := mustHasher(t, pepper(t, 1, 1))
	a, _ := h.Hash([]byte("mesma-senha"))
	b, _ := h.Hash([]byte("mesma-senha"))
	if a == b {
		t.Fatal("dois hashes da mesma senha ficaram iguais (salt repetido?)")
	}
}

func TestPepperProtectsOffline(t *testing.T) {
	// Sem a chave do pepper, o hash não confere nem com a senha certa.
	h := mustHasher(t, pepper(t, 1, 1))
	hash, _ := h.Hash([]byte("segredo"))

	semPepper := mustHasher(t, nil)
	if _, _, err := semPepper.Verify([]byte("segredo"), hash); !errors.Is(err, nil) && err == nil {
		t.Skip()
	}
	_, _, err := semPepper.Verify([]byte("segredo"), hash)
	if err == nil {
		t.Fatal("hash com pepper foi verificável sem o pepper")
	}

	// Pepper com chave diferente também falha.
	outra, _ := NewHMACPepper(1, map[uint16][]byte{1: bytes.Repeat([]byte{9}, 32)})
	h2 := mustHasher(t, outra)
	ok, _, err := h2.Verify([]byte("segredo"), hash)
	if err != nil || ok {
		t.Fatalf("chave de pepper errada aceitou a senha: ok=%t err=%v", ok, err)
	}
}

func TestRehashOnParamChange(t *testing.T) {
	old := mustHasher(t, pepper(t, 1, 1), WithParams(Params{Memory: 8 * 1024, Time: 1, Parallelism: 1, SaltLen: 16, KeyLen: 32}))
	hash, _ := old.Hash([]byte("s"))

	stronger := mustHasher(t, pepper(t, 1, 1), WithParams(Params{Memory: 16 * 1024, Time: 3, Parallelism: 1, SaltLen: 16, KeyLen: 32}))
	ok, rehash, err := stronger.Verify([]byte("s"), hash)
	if err != nil || !ok {
		t.Fatalf("verify: ok=%t err=%v", ok, err)
	}
	if !rehash {
		t.Fatal("esperava needsRehash após elevar parâmetros")
	}
}

func TestRehashOnPepperRotation(t *testing.T) {
	v1 := mustHasher(t, pepper(t, 1, 1))
	hash, _ := v1.Hash([]byte("s"))

	// Rotaciona para a versão 2, mantendo a 1 para verificar hashes antigos.
	rotated := mustHasher(t, pepper(t, 2, 1, 2))
	ok, rehash, err := rotated.Verify([]byte("s"), hash)
	if err != nil || !ok {
		t.Fatalf("verify após rotação: ok=%t err=%v", ok, err)
	}
	if !rehash {
		t.Fatal("esperava needsRehash após rotação do pepper")
	}
	// O hash regerado usa a versão nova e não pede mais rehash.
	newHash, _ := rotated.Hash([]byte("s"))
	_, rehash2, _ := rotated.Verify([]byte("s"), newHash)
	if rehash2 {
		t.Fatal("hash novo ainda pede rehash")
	}
}

func TestVerifyRejectsMalformed(t *testing.T) {
	h := mustHasher(t, pepper(t, 1, 1))
	for _, bad := range []string{
		"", "não-é-phc", "$argon2i$v=19$m=8,t=1,p=1,k=1$c2FsdA$aGFzaA",
		"$argon2id$v=18$m=8,t=1,p=1,k=1$c2FsdA$aGFzaA",
		"$argon2id$v=19$m=8,t=1,p=1$c2FsdA$aGFzaA",
		"$argon2id$v=19$m=8,t=1,p=1,k=1$!!!$aGFzaA",
	} {
		if _, _, err := h.Verify([]byte("x"), bad); err == nil {
			t.Errorf("hash malformado aceito: %q", bad)
		}
	}
}

func TestNewHMACPepperValidation(t *testing.T) {
	short := map[uint16][]byte{1: bytes.Repeat([]byte{1}, 31)}
	if _, err := NewHMACPepper(1, short); err == nil {
		t.Error("chave curta aceita")
	}
	if _, err := NewHMACPepper(0, map[uint16][]byte{1: bytes.Repeat([]byte{1}, 32)}); err == nil {
		t.Error("versão atual 0 aceita")
	}
	if _, err := NewHMACPepper(2, map[uint16][]byte{1: bytes.Repeat([]byte{1}, 32)}); err == nil {
		t.Error("versão atual sem chave aceita")
	}
}

func TestNewHasherRejectsWeakParams(t *testing.T) {
	if _, err := NewHasher(nil, WithParams(Params{Memory: 1024, Time: 1, Parallelism: 1, SaltLen: 16, KeyLen: 32})); err == nil {
		t.Error("memória fraca aceita")
	}
	if _, err := NewHasher(nil, WithParams(Params{Memory: 8 * 1024, Time: 1, Parallelism: 1, SaltLen: 8, KeyLen: 32})); err == nil {
		t.Error("salt curto aceito")
	}
}
