package store

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/util/keys"
)

// ---------------------------------------------------------------------------
// IdentityStore

func (s *Store) addrKey(address string) (signalAddr, []byte, error) {
	a, err := parseAddress(address)
	if err != nil {
		return a, nil, err
	}
	ui, err := s.idx(idxSignalUser, a.user)
	return a, ui, err
}

func (s *Store) PutIdentity(ctx context.Context, address string, key [32]byte) error {
	a, ui, err := s.addrKey(address)
	if err != nil {
		return err
	}
	enc, err := s.seal(key[:], "identity_keys", ui, deviceBytes(a.device))
	if err != nil {
		return err
	}
	return s.write(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO wa.identity_keys (instance_id, tenant_id, user_idx, device, identity_enc)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (instance_id, user_idx, device) DO UPDATE SET identity_enc = excluded.identity_enc`,
			s.instanceID, s.tenantID, ui, a.device, enc)
		return err
	})
}

// DeleteAllIdentities apaga as identidades de todos os aparelhos de um usuário.
func (s *Store) DeleteAllIdentities(ctx context.Context, phone string) error {
	ui, err := s.idx(idxSignalUser, phone)
	if err != nil {
		return err
	}
	return s.write(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM wa.identity_keys WHERE instance_id = $1 AND user_idx = $2`, s.instanceID, ui)
		return err
	})
}

func (s *Store) DeleteIdentity(ctx context.Context, address string) error {
	a, ui, err := s.addrKey(address)
	if err != nil {
		return err
	}
	return s.write(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM wa.identity_keys WHERE instance_id = $1 AND user_idx = $2 AND device = $3`,
			s.instanceID, ui, a.device)
		return err
	})
}

// IsTrustedIdentity: identidade desconhecida é confiável (será salva depois),
// mesmo contrato do sqlstore. Comparação em tempo constante.
func (s *Store) IsTrustedIdentity(ctx context.Context, address string, key [32]byte) (bool, error) {
	a, ui, err := s.addrKey(address)
	if err != nil {
		return false, err
	}
	var enc []byte
	err = s.read(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT identity_enc FROM wa.identity_keys WHERE instance_id = $1 AND user_idx = $2 AND device = $3`,
			s.instanceID, ui, a.device).Scan(&enc)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return true, nil
	} else if err != nil {
		return false, err
	}
	existing, err := s.open(enc, "identity_keys", ui, deviceBytes(a.device))
	if err != nil {
		return false, err
	}
	if len(existing) != 32 {
		return false, ErrInvalidLength
	}
	return subtle.ConstantTimeCompare(existing, key[:]) == 1, nil
}

// ---------------------------------------------------------------------------
// SessionStore

func (s *Store) GetSession(ctx context.Context, address string) ([]byte, error) {
	a, ui, err := s.addrKey(address)
	if err != nil {
		return nil, err
	}
	var enc []byte
	err = s.read(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT session_enc FROM wa.sessions WHERE instance_id = $1 AND user_idx = $2 AND device = $3`,
			s.instanceID, ui, a.device).Scan(&enc)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	} else if err != nil || enc == nil {
		return nil, err
	}
	return s.open(enc, "sessions", ui, deviceBytes(a.device))
}

func (s *Store) HasSession(ctx context.Context, address string) (bool, error) {
	a, ui, err := s.addrKey(address)
	if err != nil {
		return false, err
	}
	var has bool
	err = s.read(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT true FROM wa.sessions WHERE instance_id = $1 AND user_idx = $2 AND device = $3`,
			s.instanceID, ui, a.device).Scan(&has)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return has, err
}

// GetManySessions devolve um mapa com todos os endereços pedidos (nil para os
// que não existem). Entrada vazia devolve nil, nil — mesmo contrato do sqlstore.
func (s *Store) GetManySessions(ctx context.Context, addresses []string) (map[string][]byte, error) {
	if len(addresses) == 0 {
		return nil, nil
	}
	type key struct {
		idx string
		dev int32
	}
	byKey := make(map[key][]string, len(addresses))
	idxs := make([][]byte, 0, len(addresses))
	devs := make([]int32, 0, len(addresses))
	result := make(map[string][]byte, len(addresses))
	for _, addr := range addresses {
		a, ui, err := s.addrKey(addr)
		if err != nil {
			return nil, err
		}
		k := key{string(ui), a.device}
		if _, seen := byKey[k]; !seen {
			idxs = append(idxs, ui)
			devs = append(devs, a.device)
		}
		byKey[k] = append(byKey[k], addr)
		result[addr] = nil
	}
	err := s.read(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT user_idx, device, session_enc FROM wa.sessions
			WHERE instance_id = $1 AND (user_idx, device) IN (SELECT * FROM unnest($2::bytea[], $3::int[]))`,
			s.instanceID, idxs, devs)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var ui, enc []byte
			var dev int32
			if err := rows.Scan(&ui, &dev, &enc); err != nil {
				return err
			}
			if enc == nil {
				continue
			}
			pt, err := s.open(enc, "sessions", ui, deviceBytes(dev))
			if err != nil {
				return err
			}
			for _, addr := range byKey[key{string(ui), dev}] {
				result[addr] = pt
			}
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (s *Store) PutManySessions(ctx context.Context, sessions map[string][]byte) error {
	return s.DoTxn(ctx, func(ctx context.Context) error {
		for addr, sess := range sessions {
			if err := s.PutSession(ctx, addr, sess); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) PutSession(ctx context.Context, address string, session []byte) error {
	a, ui, err := s.addrKey(address)
	if err != nil {
		return err
	}
	var enc []byte
	if session != nil {
		if enc, err = s.seal(session, "sessions", ui, deviceBytes(a.device)); err != nil {
			return err
		}
	}
	return s.write(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO wa.sessions (instance_id, tenant_id, user_idx, device, session_enc)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (instance_id, user_idx, device) DO UPDATE SET session_enc = excluded.session_enc`,
			s.instanceID, s.tenantID, ui, a.device, enc)
		return err
	})
}

func (s *Store) DeleteAllSessions(ctx context.Context, phone string) error {
	ui, err := s.idx(idxSignalUser, phone)
	if err != nil {
		return err
	}
	return s.write(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM wa.sessions WHERE instance_id = $1 AND user_idx = $2`, s.instanceID, ui)
		return err
	})
}

func (s *Store) DeleteSession(ctx context.Context, address string) error {
	a, ui, err := s.addrKey(address)
	if err != nil {
		return err
	}
	return s.write(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM wa.sessions WHERE instance_id = $1 AND user_idx = $2 AND device = $3`,
			s.instanceID, ui, a.device)
		return err
	})
}

// MigratePNToLID move sessões, identidades e sender keys do usuário-telefone
// para o usuário-LID, recifrando cada valor com o AAD novo. Sobrescreve o que
// já existir no destino e apaga a origem, como o sqlstore. Executa uma vez por
// telefone durante a vida do Store.
func (s *Store) MigratePNToLID(ctx context.Context, pn, lid types.JID) error {
	pnUser, lidUser := pn.SignalAddressUser(), lid.SignalAddressUser()
	s.migratedMu.Lock()
	if _, done := s.migratedPN[pnUser]; done {
		s.migratedMu.Unlock()
		return nil
	}
	s.migratedPN[pnUser] = struct{}{}
	s.migratedMu.Unlock()

	from, err := s.idx(idxSignalUser, pnUser)
	if err != nil {
		return err
	}
	to, err := s.idx(idxSignalUser, lidUser)
	if err != nil {
		return err
	}
	var nSess, nIdent, nSender int
	err = s.DoTxn(ctx, func(ctx context.Context) error {
		return s.write(ctx, func(ctx context.Context, tx pgx.Tx) error {
			var err error
			if nSess, err = s.migrateUserRows(ctx, tx, "sessions", "session_enc", from, to); err != nil {
				return fmt.Errorf("migrar sessões: %w", err)
			}
			if nIdent, err = s.migrateUserRows(ctx, tx, "identity_keys", "identity_enc", from, to); err != nil {
				return fmt.Errorf("migrar identidades: %w", err)
			}
			if nSender, err = s.migrateSenderKeys(ctx, tx, from, to); err != nil {
				return fmt.Errorf("migrar sender keys: %w", err)
			}
			return nil
		})
	})
	if err != nil {
		s.migratedMu.Lock()
		delete(s.migratedPN, pnUser)
		s.migratedMu.Unlock()
		return err
	}
	s.log.Debug("migração telefone→LID concluída",
		slog.Int("sessoes", nSess), slog.Int("identidades", nIdent), slog.Int("sender_keys", nSender))
	return nil
}

// migrateUserRows serve sessions e identity_keys (mesma forma de chave).
func (s *Store) migrateUserRows(ctx context.Context, tx pgx.Tx, table, col string, from, to []byte) (int, error) {
	rows, err := tx.Query(ctx, fmt.Sprintf(`SELECT device, %s FROM wa.%s WHERE instance_id = $1 AND user_idx = $2`, col, table),
		s.instanceID, from)
	if err != nil {
		return 0, err
	}
	type row struct {
		dev int32
		enc []byte
	}
	var found []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.dev, &r.enc); err != nil {
			rows.Close()
			return 0, err
		}
		found = append(found, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	for _, r := range found {
		var newEnc []byte
		if r.enc != nil {
			pt, err := s.open(r.enc, table, from, deviceBytes(r.dev))
			if err != nil {
				return 0, err
			}
			if newEnc, err = s.seal(pt, table, to, deviceBytes(r.dev)); err != nil {
				return 0, err
			}
		}
		_, err := tx.Exec(ctx, fmt.Sprintf(`
			INSERT INTO wa.%[1]s (instance_id, tenant_id, user_idx, device, %[2]s) VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (instance_id, user_idx, device) DO UPDATE SET %[2]s = excluded.%[2]s`, table, col),
			s.instanceID, s.tenantID, to, r.dev, newEnc)
		if err != nil {
			return 0, err
		}
	}
	if _, err := tx.Exec(ctx, fmt.Sprintf(`DELETE FROM wa.%s WHERE instance_id = $1 AND user_idx = $2`, table), s.instanceID, from); err != nil {
		return 0, err
	}
	return len(found), nil
}

func (s *Store) migrateSenderKeys(ctx context.Context, tx pgx.Tx, from, to []byte) (int, error) {
	rows, err := tx.Query(ctx, `SELECT chat_idx, sender_device, sender_key_enc FROM wa.sender_keys WHERE instance_id = $1 AND sender_user_idx = $2`,
		s.instanceID, from)
	if err != nil {
		return 0, err
	}
	type row struct {
		chat []byte
		dev  int32
		enc  []byte
	}
	var found []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.chat, &r.dev, &r.enc); err != nil {
			rows.Close()
			return 0, err
		}
		found = append(found, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	for _, r := range found {
		pt, err := s.open(r.enc, "sender_keys", r.chat, from, deviceBytes(r.dev))
		if err != nil {
			return 0, err
		}
		newEnc, err := s.seal(pt, "sender_keys", r.chat, to, deviceBytes(r.dev))
		if err != nil {
			return 0, err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO wa.sender_keys (instance_id, tenant_id, chat_idx, sender_user_idx, sender_device, sender_key_enc)
			VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (instance_id, chat_idx, sender_user_idx, sender_device) DO UPDATE SET sender_key_enc = excluded.sender_key_enc`,
			s.instanceID, s.tenantID, r.chat, to, r.dev, newEnc); err != nil {
			return 0, err
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM wa.sender_keys WHERE instance_id = $1 AND sender_user_idx = $2`, s.instanceID, from); err != nil {
		return 0, err
	}
	return len(found), nil
}

// ---------------------------------------------------------------------------
// PreKeyStore

func preKeyAAD(id uint32) []byte { return binary.BigEndian.AppendUint32(nil, id) }

func (s *Store) insertPreKey(ctx context.Context, tx pgx.Tx, id uint32, uploaded bool) (*keys.PreKey, error) {
	key := keys.NewPreKey(id)
	enc, err := s.seal(key.Priv[:], "pre_keys", preKeyAAD(id))
	if err != nil {
		return nil, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO wa.pre_keys (instance_id, tenant_id, key_id, key_enc, uploaded) VALUES ($1, $2, $3, $4, $5)`,
		s.instanceID, s.tenantID, int64(id), enc, uploaded)
	return key, err
}

func (s *Store) nextPreKeyID(ctx context.Context, tx pgx.Tx) (uint32, error) {
	var last *int64
	if err := tx.QueryRow(ctx, `SELECT max(key_id) FROM wa.pre_keys WHERE instance_id = $1`, s.instanceID).Scan(&last); err != nil {
		return 0, fmt.Errorf("store: próximo ID de pre-key: %w", err)
	}
	if last == nil {
		return 1, nil
	}
	return uint32(*last) + 1, nil //nolint:gosec // key_id < 2^24 pela constraint
}

func (s *Store) GenOnePreKey(ctx context.Context) (*keys.PreKey, error) {
	s.preKeyMu.Lock()
	defer s.preKeyMu.Unlock()
	var key *keys.PreKey
	err := s.write(ctx, func(ctx context.Context, tx pgx.Tx) error {
		id, err := s.nextPreKeyID(ctx, tx)
		if err != nil {
			return err
		}
		key, err = s.insertPreKey(ctx, tx, id, true)
		return err
	})
	return key, err
}

// GetOrGenPreKeys devolve até count pre-keys ainda não enviadas, gerando as
// que faltarem. Tudo numa transação.
func (s *Store) GetOrGenPreKeys(ctx context.Context, count uint32) ([]*keys.PreKey, error) {
	s.preKeyMu.Lock()
	defer s.preKeyMu.Unlock()
	var out []*keys.PreKey
	err := s.write(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT key_id, key_enc FROM wa.pre_keys WHERE instance_id = $1 AND uploaded = false ORDER BY key_id LIMIT $2`,
			s.instanceID, int64(count))
		if err != nil {
			return err
		}
		out, err = s.scanPreKeys(rows)
		if err != nil {
			return err
		}
		if uint32(len(out)) >= count { //nolint:gosec // len <= count
			return nil
		}
		next, err := s.nextPreKeyID(ctx, tx)
		if err != nil {
			return err
		}
		for uint32(len(out)) < count { //nolint:gosec // len <= count
			k, err := s.insertPreKey(ctx, tx, next, false)
			if err != nil {
				return fmt.Errorf("store: gerar pre-key: %w", err)
			}
			out = append(out, k)
			next++
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Store) scanPreKeys(rows pgx.Rows) ([]*keys.PreKey, error) {
	defer rows.Close()
	var out []*keys.PreKey
	for rows.Next() {
		var id int64
		var enc []byte
		if err := rows.Scan(&id, &enc); err != nil {
			return nil, err
		}
		k, err := s.decodePreKey(uint32(id), enc) //nolint:gosec // key_id < 2^24
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func (s *Store) decodePreKey(id uint32, enc []byte) (*keys.PreKey, error) {
	priv, err := s.open(enc, "pre_keys", preKeyAAD(id))
	if err != nil {
		return nil, err
	}
	if len(priv) != 32 {
		return nil, ErrInvalidLength
	}
	return &keys.PreKey{KeyPair: *keys.NewKeyPairFromPrivateKey(*(*[32]byte)(priv)), KeyID: id}, nil
}

func (s *Store) GetPreKey(ctx context.Context, id uint32) (*keys.PreKey, error) {
	var enc []byte
	err := s.read(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT key_enc FROM wa.pre_keys WHERE instance_id = $1 AND key_id = $2`,
			s.instanceID, int64(id)).Scan(&enc)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return s.decodePreKey(id, enc)
}

func (s *Store) RemovePreKey(ctx context.Context, id uint32) error {
	return s.write(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM wa.pre_keys WHERE instance_id = $1 AND key_id = $2`, s.instanceID, int64(id))
		return err
	})
}

func (s *Store) MarkPreKeysAsUploaded(ctx context.Context, upToID uint32) error {
	return s.write(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE wa.pre_keys SET uploaded = true WHERE instance_id = $1 AND key_id <= $2`,
			s.instanceID, int64(upToID))
		return err
	})
}

func (s *Store) UploadedPreKeyCount(ctx context.Context) (int, error) {
	var n int
	err := s.read(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM wa.pre_keys WHERE instance_id = $1 AND uploaded = true`, s.instanceID).Scan(&n)
	})
	return n, err
}

// ---------------------------------------------------------------------------
// SenderKeyStore

func (s *Store) senderKeyKeys(group, user string) (chat, senderUser []byte, a signalAddr, err error) {
	if chat, err = s.idx(idxJID, group); err != nil {
		return
	}
	a, senderUser, err = s.addrKey(user)
	return
}

func (s *Store) PutSenderKey(ctx context.Context, group, user string, session []byte) error {
	chat, su, a, err := s.senderKeyKeys(group, user)
	if err != nil {
		return err
	}
	enc, err := s.seal(session, "sender_keys", chat, su, deviceBytes(a.device))
	if err != nil {
		return err
	}
	return s.write(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO wa.sender_keys (instance_id, tenant_id, chat_idx, sender_user_idx, sender_device, sender_key_enc)
			VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (instance_id, chat_idx, sender_user_idx, sender_device) DO UPDATE SET sender_key_enc = excluded.sender_key_enc`,
			s.instanceID, s.tenantID, chat, su, a.device, enc)
		return err
	})
}

func (s *Store) GetSenderKey(ctx context.Context, group, user string) ([]byte, error) {
	chat, su, a, err := s.senderKeyKeys(group, user)
	if err != nil {
		return nil, err
	}
	var enc []byte
	err = s.read(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT sender_key_enc FROM wa.sender_keys
			WHERE instance_id = $1 AND chat_idx = $2 AND sender_user_idx = $3 AND sender_device = $4`,
			s.instanceID, chat, su, a.device).Scan(&enc)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return s.open(enc, "sender_keys", chat, su, deviceBytes(a.device))
}
