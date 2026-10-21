package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/jackc/pgx/v5"
	wastore "go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
)

// LIDMap implementa store.LIDStore POR INSTÂNCIA (ADR-0010): no sqlstore o
// mapa é global ao banco, o que aqui vazaria dados entre tenants. Mesma
// semântica de cache do CachedLIDMap do whatsmeow.
type LIDMap struct {
	s *Store

	mu          sync.RWMutex
	pnToLID     map[string]string
	lidToPN     map[string]string
	cacheFilled bool
}

var _ wastore.LIDStore = (*LIDMap)(nil)

func newLIDMap(s *Store) *LIDMap {
	return &LIDMap{s: s, pnToLID: map[string]string{}, lidToPN: map[string]string{}}
}

type lidRecord struct {
	LID string `json:"l"`
	PN  string `json:"p"`
}

func (m *LIDMap) decode(lidIdx, enc []byte) (lidRecord, error) {
	pt, err := m.s.open(enc, "lid_map", lidIdx)
	if err != nil {
		return lidRecord{}, err
	}
	var r lidRecord
	if err := json.Unmarshal(pt, &r); err != nil {
		return lidRecord{}, fmt.Errorf("store: mapeamento LID corrompido: %w", err)
	}
	return r, nil
}

// FillCache carrega todo o mapa da instância.
func (m *LIDMap) FillCache(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	err := m.s.read(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT lid_idx, mapping_enc FROM wa.lid_map WHERE instance_id = $1`, m.s.instanceID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var li, enc []byte
			if err := rows.Scan(&li, &enc); err != nil {
				return err
			}
			r, err := m.decode(li, enc)
			if err != nil {
				return err
			}
			m.pnToLID[r.PN] = r.LID
			m.lidToPN[r.LID] = r.PN
		}
		return rows.Err()
	})
	m.cacheFilled = err == nil
	return err
}

// lookup busca no cache ou no banco. fromLID indica a direção.
func (m *LIDMap) lookup(ctx context.Context, source types.JID, fromLID bool) (types.JID, error) {
	src, dst := m.pnToLID, m.lidToPN
	targetServer := types.HiddenUserServer
	domain := idxPNUser
	if fromLID {
		src, dst = m.lidToPN, m.pnToLID
		targetServer = types.DefaultUserServer
		domain = idxLIDUser
	}

	m.mu.RLock()
	target, ok := src[source.User]
	filled := m.cacheFilled
	m.mu.RUnlock()
	if ok || filled {
		if target == "" {
			return types.JID{}, nil
		}
		return types.JID{User: target, Device: source.Device, Server: targetServer}, nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	idx, err := m.s.idx(domain, source.User)
	if err != nil {
		return types.JID{}, err
	}
	col := "pn_idx"
	if fromLID {
		col = "lid_idx"
	}
	var li, enc []byte
	err = m.s.read(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, fmt.Sprintf(`SELECT lid_idx, mapping_enc FROM wa.lid_map WHERE instance_id = $1 AND %s = $2`, col),
			m.s.instanceID, idx).Scan(&li, &enc)
	})
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		target = ""
	case err != nil:
		return types.JID{}, err
	default:
		r, err := m.decode(li, enc)
		if err != nil {
			return types.JID{}, err
		}
		target = r.PN
		if !fromLID {
			target = r.LID
		}
	}
	src[source.User] = target
	if target == "" {
		return types.JID{}, nil
	}
	dst[target] = source.User
	return types.JID{User: target, Device: source.Device, Server: targetServer}, nil
}

func (m *LIDMap) GetLIDForPN(ctx context.Context, pn types.JID) (types.JID, error) {
	if pn.Server != types.DefaultUserServer {
		return types.JID{}, fmt.Errorf("store: GetLIDForPN chamado com JID que não é telefone")
	}
	return m.lookup(ctx, pn, false)
}

func (m *LIDMap) GetPNForLID(ctx context.Context, lid types.JID) (types.JID, error) {
	if lid.Server != types.HiddenUserServer {
		return types.JID{}, fmt.Errorf("store: GetPNForLID chamado com JID que não é LID")
	}
	return m.lookup(ctx, lid, true)
}

func (m *LIDMap) GetManyLIDsForPNs(ctx context.Context, pns []types.JID) (map[types.JID]types.JID, error) {
	if len(pns) == 0 {
		return nil, nil
	}
	result := make(map[types.JID]types.JID, len(pns))
	for _, pn := range pns {
		if pn.Server != types.DefaultUserServer {
			continue
		}
		lid, err := m.lookup(ctx, pn, false)
		if err != nil {
			return nil, err
		}
		if !lid.IsEmpty() {
			result[pn] = lid
		}
	}
	return result, nil
}

func validMapping(lid, pn types.JID) bool {
	return lid.Server == types.HiddenUserServer && pn.Server == types.DefaultUserServer
}

func (m *LIDMap) PutLIDMapping(ctx context.Context, lid, pn types.JID) error {
	if !validMapping(lid, pn) {
		return fmt.Errorf("store: PutLIDMapping com JIDs inválidos")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if cached, ok := m.pnToLID[pn.User]; ok && cached == lid.User {
		return nil
	}
	return m.s.write(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return m.putTx(ctx, tx, lid.User, pn.User)
	})
}

func (m *LIDMap) PutManyLIDMappings(ctx context.Context, mappings []wastore.LIDMapping) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var todo []wastore.LIDMapping
	seen := map[wastore.LIDMapping]bool{}
	for _, mp := range mappings {
		if !validMapping(mp.LID, mp.PN) {
			continue
		}
		if cached, ok := m.pnToLID[mp.PN.User]; ok && cached == mp.LID.User {
			continue
		}
		if seen[mp] {
			continue
		}
		seen[mp] = true
		todo = append(todo, mp)
	}
	if len(todo) == 0 {
		return nil
	}
	return m.s.write(ctx, func(ctx context.Context, tx pgx.Tx) error {
		for _, mp := range todo {
			if err := m.putTx(ctx, tx, mp.LID.User, mp.PN.User); err != nil {
				return err
			}
		}
		return nil
	})
}

// putTx replica unlockedPutLIDMapping do sqlstore: remove o vínculo antigo do
// telefone com outro LID e grava (ou atualiza) o do LID.
func (m *LIDMap) putTx(ctx context.Context, tx pgx.Tx, lidUser, pnUser string) error {
	li, err := m.s.idx(idxLIDUser, lidUser)
	if err != nil {
		return err
	}
	pi, err := m.s.idx(idxPNUser, pnUser)
	if err != nil {
		return err
	}
	pt, err := json.Marshal(lidRecord{LID: lidUser, PN: pnUser})
	if err != nil {
		return err
	}
	enc, err := m.s.seal(pt, "lid_map", li)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM wa.lid_map WHERE instance_id = $1 AND lid_idx <> $2 AND pn_idx = $3`,
		m.s.instanceID, li, pi); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO wa.lid_map (instance_id, tenant_id, lid_idx, pn_idx, mapping_enc) VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (instance_id, lid_idx) DO UPDATE SET pn_idx = excluded.pn_idx, mapping_enc = excluded.mapping_enc
			WHERE wa.lid_map.pn_idx <> excluded.pn_idx`,
		m.s.instanceID, m.s.tenantID, li, pi, enc); err != nil {
		return err
	}
	oldLID, oldPN := m.pnToLID[pnUser], m.lidToPN[lidUser]
	m.pnToLID[pnUser] = lidUser
	m.lidToPN[lidUser] = pnUser
	if oldPN != "" && oldPN != pnUser && m.pnToLID[oldPN] == lidUser {
		delete(m.pnToLID, oldPN)
	}
	if oldLID != "" && oldLID != lidUser && m.lidToPN[oldLID] == pnUser {
		delete(m.lidToPN, oldLID)
	}
	return nil
}
