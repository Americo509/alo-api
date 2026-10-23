// Package session gerencia sessões opacas do painel (ADR-0007, item 7 e
// ADR-0009): o navegador guarda só um ID aleatório num cookie; todo o estado
// fica no servidor (Redis). O ID nunca é gravado em claro — o backend guarda
// só o hash SHA-256 dele, então um dump do Redis não entrega sessões válidas.
//
// Suporta expiração por inatividade e expiração absoluta, rotação do ID
// (anti-fixação) e revogação imediata, individual ou de todas as sessões de
// um usuário ("encerrar todas").
package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/Americo509/alo-api/internal/clock"
)

// ErrNotFound indica sessão inexistente, expirada ou revogada.
var ErrNotFound = errors.New("session: sessão inválida")

const (
	idBytes      = 32 // 256 bits
	keyPrefix    = "sess:"
	userSetPref  = "usess:" // índice de sessões por usuário, para "encerrar todas"
	minLifetimes = time.Minute
)

// Data é o estado de uma sessão.
type Data struct {
	UserID       uuid.UUID `json:"uid"`
	CreatedAt    time.Time `json:"cat"`
	LastSeenAt   time.Time `json:"lsa"`
	AbsExpiresAt time.Time `json:"abs"`
	// AMR registra como o usuário se autenticou (ex.: "pwd", "mfa", "oidc").
	AMR []string `json:"amr,omitempty"`
	// AuthAt é o instante da última autenticação FORTE (login ou reautenticação).
	// Ações sensíveis exigem que seja recente.
	AuthAt time.Time `json:"aat,omitempty"`
	// IP e UserAgent identificam o dispositivo na tela "sessões ativas". Ficam
	// só enquanto a sessão existir (no máximo Absolute).
	IP        string `json:"ip,omitempty"`
	UserAgent string `json:"ua,omitempty"`
}

// Config define os tempos de vida da sessão.
type Config struct {
	// Idle: tempo de inatividade até expirar.
	Idle time.Duration
	// Absolute: tempo total máximo, independente de atividade.
	Absolute time.Duration
}

// DefaultConfig: 30 min de inatividade, 12 h no total.
func DefaultConfig() Config { return Config{Idle: 30 * time.Minute, Absolute: 12 * time.Hour} }

func (c Config) valid() error {
	switch {
	case c.Idle < minLifetimes || c.Absolute < minLifetimes:
		return errors.New("session: tempos de vida muito curtos")
	case c.Idle > c.Absolute:
		return errors.New("session: Idle não pode ser maior que Absolute")
	}
	return nil
}

// Backend é o armazenamento das sessões (Redis em produção, memória em teste).
// Chaves são opacas; o TTL é responsabilidade do backend.
type Backend interface {
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error
	Get(ctx context.Context, key string) ([]byte, error) // ErrNotFound se ausente
	Del(ctx context.Context, keys ...string) error
	Expire(ctx context.Context, key string, ttl time.Duration) error
	SetAdd(ctx context.Context, set, member string, ttl time.Duration) error
	SetMembers(ctx context.Context, set string) ([]string, error)
	SetRem(ctx context.Context, set, member string) error
}

// Manager cria, valida, renova e revoga sessões.
type Manager struct {
	be    Backend
	cfg   Config
	clock clock.Clock
	rand  func([]byte) (int, error)
}

// Option ajusta o Manager.
type Option func(*Manager)

// WithRand troca a fonte de aleatoriedade (para testes).
func WithRand(f func([]byte) (int, error)) Option { return func(m *Manager) { m.rand = f } }

// NewManager cria o gerenciador.
func NewManager(be Backend, cfg Config, clk clock.Clock, opts ...Option) (*Manager, error) {
	if err := cfg.valid(); err != nil {
		return nil, err
	}
	if be == nil || clk == nil {
		return nil, errors.New("session: Backend e Clock são obrigatórios")
	}
	m := &Manager{be: be, cfg: cfg, clock: clk, rand: rand.Read}
	for _, o := range opts {
		o(m)
	}
	return m, nil
}

// Create abre uma sessão nova e devolve o ID (para o cookie) e os dados.
func (m *Manager) Create(ctx context.Context, userID uuid.UUID, amr ...string) (id string, d Data, err error) {
	return m.CreateWithMeta(ctx, userID, Meta{}, amr...)
}

// Get valida o ID e, em caso de sucesso, desliza a janela de inatividade.
// Devolve ErrNotFound para sessão inexistente, expirada ou revogada.
func (m *Manager) Get(ctx context.Context, id string) (Data, error) {
	key, err := keyOf(id)
	if err != nil {
		return Data{}, ErrNotFound
	}
	raw, err := m.be.Get(ctx, key)
	if err != nil {
		return Data{}, err // já é ErrNotFound quando ausente
	}
	var d Data
	if err := json.Unmarshal(raw, &d); err != nil {
		return Data{}, fmt.Errorf("session: estado corrompido: %w", err)
	}
	now := m.clock.Now()
	if !now.Before(d.AbsExpiresAt) {
		_ = m.revoke(ctx, key, d.UserID)
		return Data{}, ErrNotFound
	}
	// Desliza a inatividade e reescreve o TTL (limitado pela expiração absoluta).
	d.LastSeenAt = now
	ttl := m.remainingTTL(now, d.AbsExpiresAt)
	if raw, err := json.Marshal(d); err == nil {
		_ = m.be.Set(ctx, key, raw, ttl)
		_ = m.be.Expire(ctx, userSet(d.UserID), ttl)
	}
	return d, nil
}

// Rotate substitui o ID da sessão (no login e em mudança de privilégio),
// preservando o estado e atualizando o AMR. O ID antigo deixa de valer.
func (m *Manager) Rotate(ctx context.Context, oldID string, amr ...string) (newID string, d Data, err error) {
	d, err = m.Get(ctx, oldID)
	if err != nil {
		return "", Data{}, err
	}
	if len(amr) > 0 {
		d.AMR = mergeAMR(d.AMR, amr)
		d.AuthAt = m.clock.Now() // nova autenticação forte
	}
	oldKey, _ := keyOf(oldID)
	if err := m.revoke(ctx, oldKey, d.UserID); err != nil {
		return "", Data{}, err
	}
	newID, err = m.store(ctx, d)
	return newID, d, err
}

// Revoke encerra uma sessão pelo ID.
func (m *Manager) Revoke(ctx context.Context, id string) error {
	key, err := keyOf(id)
	if err != nil {
		return nil // ID inválido: nada a revogar
	}
	raw, err := m.be.Get(ctx, key)
	if errors.Is(err, ErrNotFound) {
		return nil
	} else if err != nil {
		return err
	}
	var d Data
	_ = json.Unmarshal(raw, &d)
	return m.revoke(ctx, key, d.UserID)
}

// RevokeAll encerra todas as sessões de um usuário (troca de senha, pedido do
// usuário, suspeita de comprometimento).
func (m *Manager) RevokeAll(ctx context.Context, userID uuid.UUID) error {
	set := userSet(userID)
	members, err := m.be.SetMembers(ctx, set)
	if err != nil {
		return err
	}
	keys := make([]string, 0, len(members))
	for _, mem := range members {
		keys = append(keys, keyPrefix+mem)
	}
	if len(keys) > 0 {
		if err := m.be.Del(ctx, keys...); err != nil {
			return err
		}
	}
	return m.be.Del(ctx, set)
}

func (m *Manager) store(ctx context.Context, d Data) (string, error) {
	id, key, member, err := newID(m.rand)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(d)
	if err != nil {
		return "", err
	}
	ttl := m.remainingTTL(m.clock.Now(), d.AbsExpiresAt)
	if err := m.be.Set(ctx, key, raw, ttl); err != nil {
		return "", fmt.Errorf("session: gravar: %w", err)
	}
	if err := m.be.SetAdd(ctx, userSet(d.UserID), member, m.cfg.Absolute); err != nil {
		_ = m.be.Del(ctx, key)
		return "", fmt.Errorf("session: indexar: %w", err)
	}
	return id, nil
}

func (m *Manager) revoke(ctx context.Context, key string, userID uuid.UUID) error {
	if err := m.be.Del(ctx, key); err != nil {
		return err
	}
	return m.be.SetRem(ctx, userSet(userID), key[len(keyPrefix):])
}

// remainingTTL limita a janela de inatividade pela expiração absoluta.
func (m *Manager) remainingTTL(now, abs time.Time) time.Duration {
	ttl := m.cfg.Idle
	if until := abs.Sub(now); until < ttl {
		ttl = until
	}
	return ttl
}

// --- IDs e chaves -----------------------------------------------------------

var enc = base64.RawURLEncoding

// newID gera um ID aleatório e devolve: o ID (cookie), a chave no backend
// (prefixo + hash) e o membro do índice (hash, sem prefixo).
func newID(randRead func([]byte) (int, error)) (id, key, member string, err error) {
	b := make([]byte, idBytes)
	if _, err = randRead(b); err != nil {
		return "", "", "", fmt.Errorf("session: gerar ID: %w", err)
	}
	id = enc.EncodeToString(b)
	member = hashID(b)
	return id, keyPrefix + member, member, nil
}

func keyOf(id string) (string, error) {
	b, err := enc.DecodeString(id)
	if err != nil || len(b) != idBytes {
		return "", errors.New("session: ID malformado")
	}
	return keyPrefix + hashID(b), nil
}

func hashID(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func userSet(userID uuid.UUID) string { return userSetPref + userID.String() }

func mergeAMR(existing, add []string) []string {
	seen := make(map[string]bool, len(existing)+len(add))
	out := make([]string, 0, len(existing)+len(add))
	for _, s := range append(append([]string{}, existing...), add...) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
