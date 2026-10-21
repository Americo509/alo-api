// Package envelope implementa cifragem de envelope: cada instância tem uma
// chave de dados (DEK) própria, que cifra o auth state com AES-256-GCM; a DEK
// é guardada cifrada por uma chave mestra que nunca sai do KMS/Vault.
// Vazou o banco, não vazou a sessão (ADR-0005, requisito de segurança).
package envelope

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
)

const (
	// formatV1: [0x01][nonce 12 bytes][ciphertext+tag]. O byte de formato
	// permite trocar de algoritmo no futuro sem ambiguidade.
	formatV1  byte = 0x01
	keySize        = 32
	nonceSize      = 12
	overhead       = 1 + nonceSize + 16

	// Rótulos HKDF (NIST SP 800-56C): a DEK nunca é usada direto; cada
	// finalidade tem a sua chave derivada (NIST SP 800-57, uma chave por
	// propósito).
	infoAEAD       = "zap-gateway/v1/aead"
	infoBlindIndex = "zap-gateway/v1/blind-index"
)

var (
	// ErrOpen é devolvido para qualquer falha ao abrir um dado cifrado
	// (adulteração, AAD errado, chave errada). Sem detalhes, de propósito.
	ErrOpen = errors.New("envelope: não foi possível abrir o dado cifrado")
	// ErrDestroyed indica uso de uma DataKey depois de Destroy.
	ErrDestroyed = errors.New("envelope: chave de dados já destruída")
)

// WrappedKey é a DEK cifrada pela chave mestra. É o que vai para o banco.
type WrappedKey struct {
	// MasterKeyRef identifica a chave mestra (ex.: "vault-transit:transit/sessions").
	MasterKeyRef string
	// Ciphertext é opaco; o formato depende do KeyManager.
	Ciphertext []byte
}

// KeyManager cifra e decifra DEKs com a chave mestra. Implementações: Vault
// Transit (produção e dev) e um gerenciador local só para testes.
type KeyManager interface {
	Wrap(ctx context.Context, plaintextKey []byte) (WrappedKey, error)
	Unwrap(ctx context.Context, w WrappedKey) ([]byte, error)
	// Rewrap recifra a DEK com a versão mais nova da chave mestra, sem expor a
	// DEK à aplicação. Usado na rotação da chave mestra.
	Rewrap(ctx context.Context, w WrappedKey) (WrappedKey, error)
}

// Service gera e abre DEKs.
type Service struct {
	km   KeyManager
	rand io.Reader
}

// Option ajusta o Service.
type Option func(*Service)

// WithRand troca a fonte de aleatoriedade (só para testes).
func WithRand(r io.Reader) Option { return func(s *Service) { s.rand = r } }

// New cria o serviço de envelope.
func New(km KeyManager, opts ...Option) *Service {
	s := &Service{km: km, rand: rand.Reader}
	for _, o := range opts {
		o(s)
	}
	return s
}

// GenerateKey cria uma DEK nova e devolve a versão em memória e a versão
// cifrada para persistir.
func (s *Service) GenerateKey(ctx context.Context) (*DataKey, WrappedKey, error) {
	raw := make([]byte, keySize)
	if _, err := io.ReadFull(s.rand, raw); err != nil {
		return nil, WrappedKey{}, fmt.Errorf("envelope: gerar chave de dados: %w", err)
	}
	w, err := s.km.Wrap(ctx, raw)
	if err != nil {
		clear(raw)
		return nil, WrappedKey{}, fmt.Errorf("envelope: cifrar chave de dados: %w", err)
	}
	// newDataKey apaga raw depois de derivar as subchaves.
	dk, err := newDataKey(raw, s.rand)
	if err != nil {
		return nil, WrappedKey{}, err
	}
	return dk, w, nil
}

// OpenKey decifra uma DEK persistida.
func (s *Service) OpenKey(ctx context.Context, w WrappedKey) (*DataKey, error) {
	raw, err := s.km.Unwrap(ctx, w)
	if err != nil {
		return nil, fmt.Errorf("envelope: decifrar chave de dados: %w", err)
	}
	if len(raw) != keySize {
		clear(raw)
		return nil, fmt.Errorf("envelope: chave de dados com %d bytes, esperado %d", len(raw), keySize)
	}
	return newDataKey(raw, s.rand)
}

// Rewrap recifra a DEK com a versão atual da chave mestra.
func (s *Service) Rewrap(ctx context.Context, w WrappedKey) (WrappedKey, error) {
	nw, err := s.km.Rewrap(ctx, w)
	if err != nil {
		return WrappedKey{}, fmt.Errorf("envelope: recifrar chave de dados: %w", err)
	}
	return nw, nil
}

// DataKey é uma DEK em claro, mantida só em memória pelo worker dono da
// instância. Dela saem duas chaves derivadas por HKDF-SHA256: uma para
// AES-256-GCM e outra para blind index (HMAC-SHA256). A DEK em si é apagada
// logo após a derivação. Segura para uso concorrente.
//
// Limite: nonces de 96 bits aleatórios são seguros até ~2^32 cifragens por
// chave (NIST SP 800-38D, §8.3). O auth state gera bem menos que isso por
// instância; ainda assim a DEK deve ser trocada periodicamente (re-cifrando o
// estado), o que fica a cargo do store.
type DataKey struct {
	mu   sync.RWMutex
	aead cipher.AEAD
	idx  []byte
	rand io.Reader
}

func newDataKey(raw []byte, r io.Reader) (*DataKey, error) {
	defer clear(raw)
	encKey, err := hkdf.Key(sha256.New, raw, nil, infoAEAD, keySize)
	if err != nil {
		return nil, fmt.Errorf("envelope: derivar chave de cifragem: %w", err)
	}
	defer clear(encKey)
	idxKey, err := hkdf.Key(sha256.New, raw, nil, infoBlindIndex, keySize)
	if err != nil {
		return nil, fmt.Errorf("envelope: derivar chave de índice: %w", err)
	}
	block, err := aes.NewCipher(encKey)
	if err != nil {
		clear(idxKey)
		return nil, fmt.Errorf("envelope: inicializar AES: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		clear(idxKey)
		return nil, fmt.Errorf("envelope: inicializar GCM: %w", err)
	}
	return &DataKey{aead: aead, idx: idxKey, rand: r}, nil
}

// BlindIndex devolve HMAC-SHA256(chave de índice, domínio || valor). Permite
// buscar por igualdade (ex.: telefone) sem guardar o valor. O domínio separa
// usos diferentes do mesmo valor (ex.: "contato" e "conversa").
func (k *DataKey) BlindIndex(domain string, value []byte) ([]byte, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.idx == nil {
		return nil, ErrDestroyed
	}
	m := hmac.New(sha256.New, k.idx)
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(domain))) //nolint:gosec // domínios são constantes curtas
	m.Write(n[:])
	m.Write([]byte(domain))
	m.Write(value)
	return m.Sum(nil), nil
}

// Seal cifra plaintext. aad (dado associado) não é cifrado, mas é autenticado:
// usar o ID da instância e o nome do campo impede copiar um blob de uma
// instância (ou de um campo) para outra.
func (k *DataKey) Seal(plaintext, aad []byte) ([]byte, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.aead == nil {
		return nil, ErrDestroyed
	}
	out := make([]byte, 1+nonceSize, overhead+len(plaintext))
	out[0] = formatV1
	if _, err := io.ReadFull(k.rand, out[1:1+nonceSize]); err != nil {
		return nil, fmt.Errorf("envelope: gerar nonce: %w", err)
	}
	return k.aead.Seal(out, out[1:1+nonceSize], plaintext, bindAAD(formatV1, aad)), nil
}

// Open decifra um blob produzido por Seal com o mesmo aad.
func (k *DataKey) Open(sealed, aad []byte) ([]byte, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.aead == nil {
		return nil, ErrDestroyed
	}
	if len(sealed) < overhead || sealed[0] != formatV1 {
		return nil, ErrOpen
	}
	pt, err := k.aead.Open(nil, sealed[1:1+nonceSize], sealed[1+nonceSize:], bindAAD(sealed[0], aad))
	if err != nil {
		return nil, ErrOpen
	}
	return pt, nil
}

// Destroy zera a chave em memória (melhor esforço: o Go não garante que não
// existam cópias feitas pelo runtime) e impede uso posterior.
func (k *DataKey) Destroy() {
	k.mu.Lock()
	defer k.mu.Unlock()
	clear(k.idx)
	k.idx = nil
	k.aead = nil
}

// bindAAD inclui o byte de formato no dado autenticado, para que trocar o
// formato de um blob também invalide a autenticação.
func bindAAD(format byte, aad []byte) []byte {
	b := make([]byte, 0, 1+len(aad))
	b = append(b, format)
	return append(b, aad...)
}
