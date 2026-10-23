// Package envelopetest fornece um KeyManager em memória para testes.
// NUNCA usar em produção: a chave mestra fica no processo.
package envelopetest

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"

	"github.com/Americo509/alo-api/internal/crypto/envelope"
)

const refPrefix = "local-test:v"

// LocalKeyManager imita um KMS com chave mestra versionada.
type LocalKeyManager struct {
	mu       sync.Mutex
	versions [][]byte // índice 0 = v1
	// FailNext faz a próxima chamada falhar com este erro (simula KMS fora).
	FailNext error
}

// New cria um gerenciador com uma versão de chave mestra.
func New() *LocalKeyManager {
	m := &LocalKeyManager{}
	m.Rotate()
	return m
}

// Rotate adiciona uma nova versão de chave mestra; Wrap passa a usá-la.
func (m *LocalKeyManager) Rotate() {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		panic(err)
	}
	m.versions = append(m.versions, k)
}

func (m *LocalKeyManager) Wrap(_ context.Context, pt []byte) (envelope.WrappedKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.takeFailure(); err != nil {
		return envelope.WrappedKey{}, err
	}
	v := len(m.versions)
	ct, err := seal(m.versions[v-1], pt)
	if err != nil {
		return envelope.WrappedKey{}, err
	}
	return envelope.WrappedKey{MasterKeyRef: refPrefix + strconv.Itoa(v), Ciphertext: ct}, nil
}

func (m *LocalKeyManager) Unwrap(_ context.Context, w envelope.WrappedKey) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.takeFailure(); err != nil {
		return nil, err
	}
	key, err := m.keyFor(w.MasterKeyRef)
	if err != nil {
		return nil, err
	}
	return open(key, w.Ciphertext)
}

func (m *LocalKeyManager) Rewrap(ctx context.Context, w envelope.WrappedKey) (envelope.WrappedKey, error) {
	pt, err := m.Unwrap(ctx, w)
	if err != nil {
		return envelope.WrappedKey{}, err
	}
	defer clear(pt)
	return m.Wrap(ctx, pt)
}

func (m *LocalKeyManager) takeFailure() error {
	err := m.FailNext
	m.FailNext = nil
	return err
}

func (m *LocalKeyManager) keyFor(ref string) ([]byte, error) {
	if !strings.HasPrefix(ref, refPrefix) {
		return nil, fmt.Errorf("referência de chave mestra desconhecida: %q", ref)
	}
	v, err := strconv.Atoi(strings.TrimPrefix(ref, refPrefix))
	if err != nil || v < 1 || v > len(m.versions) {
		return nil, fmt.Errorf("versão de chave mestra inexistente: %q", ref)
	}
	return m.versions[v-1], nil
}

func seal(key, pt []byte) ([]byte, error) {
	aead, err := gcm(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, pt, nil), nil
}

func open(key, ct []byte) ([]byte, error) {
	aead, err := gcm(key)
	if err != nil {
		return nil, err
	}
	if len(ct) < aead.NonceSize() {
		return nil, errors.New("ciphertext curto")
	}
	return aead.Open(nil, ct[:aead.NonceSize()], ct[aead.NonceSize():], nil)
}

func gcm(key []byte) (cipher.AEAD, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}
