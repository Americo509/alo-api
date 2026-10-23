// Package ephemeral guarda estado de curta duração e de USO ÚNICO dos fluxos
// de autenticação: desafios de passkey (WebAuthn) e state/nonce/PKCE do login
// federado. Quem lê consome: Take devolve o valor e o apaga atomicamente, então
// uma cerimônia ou um callback não pode ser repetido (anti-replay).
package ephemeral

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/Americo509/alo-api/internal/clock"
)

// ErrNotFound: chave inexistente, expirada ou já consumida.
var ErrNotFound = errors.New("ephemeral: não encontrado, expirado ou já usado")

// Store é o armazenamento de estado efêmero.
type Store interface {
	// Put grava value sob key com TTL. Sobrescreve se já existir.
	Put(ctx context.Context, key string, value []byte, ttl time.Duration) error
	// Take devolve o valor e o remove numa operação atômica.
	Take(ctx context.Context, key string) ([]byte, error)
}

// NewToken gera um identificador aleatório de 256 bits (URL-safe) e a chave de
// armazenamento correspondente, que é o HASH do identificador: o identificador
// vai ao cliente; no backend só fica o hash.
func NewToken(randRead func([]byte) (int, error)) (token, key string, err error) {
	if randRead == nil {
		randRead = rand.Read
	}
	b := make([]byte, 32)
	if _, err = randRead(b); err != nil {
		return "", "", fmt.Errorf("ephemeral: gerar token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), hashKey(b), nil
}

// KeyOf devolve a chave de armazenamento de um token recebido do cliente.
func KeyOf(token string) (string, error) {
	b, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(b) != 32 {
		return "", ErrNotFound
	}
	return hashKey(b), nil
}

func hashKey(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// --- memória -----------------------------------------------------------------

// Memory é um Store em memória com expiração pelo relógio injetado.
type Memory struct {
	mu    sync.Mutex
	clock clock.Clock
	m     map[string]entry
}

type entry struct {
	v       []byte
	expires time.Time
}

// NewMemory cria o Store de memória.
func NewMemory(clk clock.Clock) *Memory { return &Memory{clock: clk, m: map[string]entry{}} }

func (s *Memory) Put(_ context.Context, key string, value []byte, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[key] = entry{v: append([]byte(nil), value...), expires: s.clock.Now().Add(ttl)}
	return nil
}

func (s *Memory) Take(_ context.Context, key string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[key]
	delete(s.m, key)
	if !ok || !s.clock.Now().Before(e.expires) {
		return nil, ErrNotFound
	}
	return e.v, nil
}

// --- Redis -------------------------------------------------------------------

// Redis implementa Store no Redis; Take usa GETDEL (atômico, Redis >= 6.2).
type Redis struct {
	rdb    redis.UniversalClient
	prefix string
}

// NewRedis cria o Store do Redis. prefix separa ambientes e usos.
func NewRedis(rdb redis.UniversalClient, prefix string) *Redis {
	return &Redis{rdb: rdb, prefix: prefix}
}

func (s *Redis) k(key string) string { return s.prefix + ":eph:" + key }

func (s *Redis) Put(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	return s.rdb.Set(ctx, s.k(key), value, ttl).Err()
}

func (s *Redis) Take(ctx context.Context, key string) ([]byte, error) {
	v, err := s.rdb.GetDel(ctx, s.k(key)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrNotFound
	}
	return v, err
}
