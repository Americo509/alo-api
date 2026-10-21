package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/jackc/pgx/v5"
	wastore "go.mau.fi/whatsmeow/store"
)

// ---------------------------------------------------------------------------
// AppStateSyncKeyStore

type syncKeyRecord struct {
	Data        []byte `json:"d"`
	Fingerprint []byte `json:"f"`
}

func (s *Store) PutAppStateSyncKey(ctx context.Context, id []byte, key wastore.AppStateSyncKey) error {
	pt, err := json.Marshal(syncKeyRecord{Data: key.Data, Fingerprint: key.Fingerprint})
	if err != nil {
		return err
	}
	enc, err := s.seal(pt, "app_state_sync_keys", id)
	clear(pt)
	if err != nil {
		return err
	}
	return s.write(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO wa.app_state_sync_keys (instance_id, tenant_id, key_id, key_enc, ts) VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (instance_id, key_id) DO UPDATE SET key_enc = excluded.key_enc, ts = excluded.ts
				WHERE excluded.ts > wa.app_state_sync_keys.ts`,
			s.instanceID, s.tenantID, id, enc, key.Timestamp)
		return err
	})
}

func (s *Store) decodeSyncKey(id, enc []byte, ts int64) (*wastore.AppStateSyncKey, error) {
	pt, err := s.open(enc, "app_state_sync_keys", id)
	if err != nil {
		return nil, err
	}
	defer clear(pt)
	var r syncKeyRecord
	if err := json.Unmarshal(pt, &r); err != nil {
		return nil, fmt.Errorf("store: sync key corrompida: %w", err)
	}
	return &wastore.AppStateSyncKey{Data: r.Data, Fingerprint: r.Fingerprint, Timestamp: ts}, nil
}

func (s *Store) GetAllAppStateSyncKeys(ctx context.Context) ([]*wastore.AppStateSyncKey, error) {
	var out []*wastore.AppStateSyncKey
	err := s.read(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT key_id, key_enc, ts FROM wa.app_state_sync_keys WHERE instance_id = $1 ORDER BY ts DESC`, s.instanceID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id, enc []byte
			var ts int64
			if err := rows.Scan(&id, &enc, &ts); err != nil {
				return err
			}
			k, err := s.decodeSyncKey(id, enc, ts)
			if err != nil {
				return err
			}
			out = append(out, k)
		}
		return rows.Err()
	})
	return out, err
}

func (s *Store) GetAppStateSyncKey(ctx context.Context, id []byte) (*wastore.AppStateSyncKey, error) {
	var enc []byte
	var ts int64
	err := s.read(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT key_enc, ts FROM wa.app_state_sync_keys WHERE instance_id = $1 AND key_id = $2`,
			s.instanceID, id).Scan(&enc, &ts)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return s.decodeSyncKey(id, enc, ts)
}

func (s *Store) GetLatestAppStateSyncKeyID(ctx context.Context) ([]byte, error) {
	var id []byte
	err := s.read(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT key_id FROM wa.app_state_sync_keys WHERE instance_id = $1 ORDER BY ts DESC LIMIT 1`,
			s.instanceID).Scan(&id)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return id, err
}

// ---------------------------------------------------------------------------
// AppStateStore (hashes e MACs: não são segredo nem PII, ficam em claro)

func (s *Store) PutAppStateVersion(ctx context.Context, name string, version uint64, hash [128]byte) error {
	return s.write(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO wa.app_state_version (instance_id, tenant_id, name, version, hash) VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (instance_id, name) DO UPDATE SET version = excluded.version, hash = excluded.hash`,
			s.instanceID, s.tenantID, name, int64(version), hash[:]) //nolint:gosec // versões cabem em int64
		return err
	})
}

// GetAppStateVersion: sem registro, devolve versão 0 e hash zerado (estado
// inicial correto), como o sqlstore.
func (s *Store) GetAppStateVersion(ctx context.Context, name string) (uint64, [128]byte, error) {
	var version int64
	var raw []byte
	var hash [128]byte
	err := s.read(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT version, hash FROM wa.app_state_version WHERE instance_id = $1 AND name = $2`,
			s.instanceID, name).Scan(&version, &raw)
	})
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return 0, hash, nil
	case err != nil:
		return 0, hash, err
	case len(raw) != 128:
		return 0, hash, ErrInvalidLength
	case version <= 0:
		return 0, hash, fmt.Errorf("store: versão %d inválida salva para o app state %q", version, name)
	}
	copy(hash[:], raw)
	return uint64(version), hash, nil //nolint:gosec // version > 0 checado acima
}

func (s *Store) DeleteAppStateVersion(ctx context.Context, name string) error {
	return s.write(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM wa.app_state_version WHERE instance_id = $1 AND name = $2`, s.instanceID, name)
		return err
	})
}

const mutationBatchSize = 400

func (s *Store) PutAppStateMutationMACs(ctx context.Context, name string, version uint64, mutations []wastore.AppStateMutationMAC) error {
	if len(mutations) == 0 {
		return nil
	}
	return s.write(ctx, func(ctx context.Context, tx pgx.Tx) error {
		for chunk := range slices.Chunk(mutations, mutationBatchSize) {
			idx := make([][]byte, len(chunk))
			val := make([][]byte, len(chunk))
			for i, m := range chunk {
				idx[i], val[i] = m.IndexMAC, m.ValueMAC
			}
			_, err := tx.Exec(ctx, `
				INSERT INTO wa.app_state_mutation_macs (instance_id, tenant_id, name, version, index_mac, value_mac)
				SELECT $1, $2, $3, $4, i, v FROM unnest($5::bytea[], $6::bytea[]) AS t(i, v)`,
				s.instanceID, s.tenantID, name, int64(version), idx, val) //nolint:gosec // versões cabem em int64
			if err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) DeleteAppStateMutationMACs(ctx context.Context, name string, indexMACs [][]byte) error {
	if len(indexMACs) == 0 {
		return nil
	}
	return s.write(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM wa.app_state_mutation_macs WHERE instance_id = $1 AND name = $2 AND index_mac = ANY($3::bytea[])`,
			s.instanceID, name, indexMACs)
		return err
	})
}

func (s *Store) GetAppStateMutationMAC(ctx context.Context, name string, indexMAC []byte) ([]byte, error) {
	var v []byte
	err := s.read(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT value_mac FROM wa.app_state_mutation_macs
			WHERE instance_id = $1 AND name = $2 AND index_mac = $3 ORDER BY version DESC LIMIT 1`,
			s.instanceID, name, indexMAC).Scan(&v)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return v, err
}
