package session

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

// Meta descreve a origem de uma sessão (para a tela "sessões ativas").
type Meta struct {
	IP        string
	UserAgent string
}

// Info é uma sessão como o usuário a vê. Handle identifica a sessão para
// encerrá-la; é o hash do ID (não permite reconstituir o cookie).
type Info struct {
	Handle     string
	CreatedAt  time.Time
	LastSeenAt time.Time
	AuthAt     time.Time
	IP         string
	UserAgent  string
}

const maxUserAgent = 200

// cleanMeta valida o IP e limpa o User-Agent (dado não confiável do cliente).
func cleanMeta(m Meta) Meta {
	out := Meta{}
	if a, err := netip.ParseAddr(strings.TrimSpace(m.IP)); err == nil {
		out.IP = a.String()
	}
	ua := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == utf8.RuneError {
			return -1
		}
		return r
	}, m.UserAgent)
	if utf8.RuneCountInString(ua) > maxUserAgent {
		ua = string([]rune(ua)[:maxUserAgent])
	}
	out.UserAgent = ua
	return out
}

// CreateWithMeta abre uma sessão guardando IP e User-Agent. A autenticação
// forte conta a partir de agora (AuthAt).
func (m *Manager) CreateWithMeta(ctx context.Context, userID uuid.UUID, meta Meta, amr ...string) (id string, d Data, err error) {
	now := m.clock.Now()
	meta = cleanMeta(meta)
	d = Data{
		UserID: userID, CreatedAt: now, LastSeenAt: now, AbsExpiresAt: now.Add(m.cfg.Absolute),
		AMR: amr, AuthAt: now, IP: meta.IP, UserAgent: meta.UserAgent,
	}
	id, err = m.store(ctx, d)
	return id, d, err
}

// Fresh informa se a autenticação forte da sessão é mais recente que maxAge.
func (m *Manager) Fresh(d Data, maxAge time.Duration) bool {
	return !d.AuthAt.IsZero() && m.clock.Now().Sub(d.AuthAt) <= maxAge
}

// Reauth registra uma nova autenticação forte na sessão (senha, TOTP ou
// passkey conferidos agora), sem trocar o ID nem mexer nas expirações.
func (m *Manager) Reauth(ctx context.Context, id string, amr ...string) (Data, error) {
	key, err := keyOf(id)
	if err != nil {
		return Data{}, ErrNotFound
	}
	raw, err := m.be.Get(ctx, key)
	if err != nil {
		return Data{}, err
	}
	var d Data
	if err := json.Unmarshal(raw, &d); err != nil {
		return Data{}, err
	}
	now := m.clock.Now()
	if !now.Before(d.AbsExpiresAt) {
		_ = m.revoke(ctx, key, d.UserID)
		return Data{}, ErrNotFound
	}
	d.AuthAt = now
	if len(amr) > 0 {
		d.AMR = mergeAMR(d.AMR, amr)
	}
	out, err := json.Marshal(d)
	if err != nil {
		return Data{}, err
	}
	if err := m.be.Set(ctx, key, out, m.remainingTTL(now, d.AbsExpiresAt)); err != nil {
		return Data{}, err
	}
	return d, nil
}

// HandleOf devolve o handle da sessão de um ID (para marcar a "atual").
func HandleOf(id string) (string, error) {
	key, err := keyOf(id)
	if err != nil {
		return "", ErrNotFound
	}
	return key[len(keyPrefix):], nil
}

// List devolve as sessões ativas do usuário, da mais recente para a mais
// antiga. Entradas do índice cujas sessões já expiraram são limpas.
func (m *Manager) List(ctx context.Context, userID uuid.UUID) ([]Info, error) {
	members, err := m.be.SetMembers(ctx, userSet(userID))
	if err != nil {
		return nil, err
	}
	var out []Info
	for _, mem := range members {
		raw, err := m.be.Get(ctx, keyPrefix+mem)
		if errors.Is(err, ErrNotFound) {
			_ = m.be.SetRem(ctx, userSet(userID), mem)
			continue
		} else if err != nil {
			return nil, err
		}
		var d Data
		if json.Unmarshal(raw, &d) != nil || d.UserID != userID {
			continue
		}
		out = append(out, Info{
			Handle: mem, CreatedAt: d.CreatedAt, LastSeenAt: d.LastSeenAt,
			AuthAt: d.AuthAt, IP: d.IP, UserAgent: d.UserAgent,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeenAt.After(out[j].LastSeenAt) })
	return out, nil
}

func validHandle(h string) bool {
	if len(h) != 64 {
		return false
	}
	for _, c := range h {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// RevokeHandle encerra UMA sessão do usuário pelo handle. Só encerra sessões
// que pertencem ao usuário informado (ErrNotFound caso contrário).
func (m *Manager) RevokeHandle(ctx context.Context, userID uuid.UUID, handle string) error {
	if !validHandle(handle) {
		return ErrNotFound
	}
	members, err := m.be.SetMembers(ctx, userSet(userID))
	if err != nil {
		return err
	}
	for _, mem := range members {
		if mem == handle {
			return m.revoke(ctx, keyPrefix+mem, userID)
		}
	}
	return ErrNotFound
}

// RevokeAllExcept encerra todas as sessões do usuário menos a de keepID
// (trocar senha, "sair dos outros dispositivos").
func (m *Manager) RevokeAllExcept(ctx context.Context, userID uuid.UUID, keepID string) error {
	keep, err := HandleOf(keepID)
	if err != nil {
		keep = ""
	}
	members, err := m.be.SetMembers(ctx, userSet(userID))
	if err != nil {
		return err
	}
	for _, mem := range members {
		if mem == keep {
			continue
		}
		if err := m.revoke(ctx, keyPrefix+mem, userID); err != nil {
			return err
		}
	}
	return nil
}
