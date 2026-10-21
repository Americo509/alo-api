package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	wastore "go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
)

// ---------------------------------------------------------------------------
// ContactStore. Nomes e telefone mascarado são PII: o registro inteiro (com o
// JID, para GetAllContacts) vai num blob cifrado; a busca é por blind index.

type contactRecord struct {
	JID           string `json:"j"`
	FirstName     string `json:"f,omitempty"`
	FullName      string `json:"n,omitempty"`
	PushName      string `json:"p,omitempty"`
	BusinessName  string `json:"b,omitempty"`
	RedactedPhone string `json:"r,omitempty"`
	found         bool
}

func (r *contactRecord) info() types.ContactInfo {
	return types.ContactInfo{
		Found:         r.found,
		FirstName:     r.FirstName,
		FullName:      r.FullName,
		PushName:      r.PushName,
		BusinessName:  r.BusinessName,
		RedactedPhone: r.RedactedPhone,
	}
}

func (s *Store) loadContactTx(ctx context.Context, tx pgx.Tx, jid string, idx []byte, lock bool) (*contactRecord, error) {
	q := `SELECT contact_enc FROM wa.contacts WHERE instance_id = $1 AND jid_idx = $2`
	if lock {
		q += ` FOR UPDATE`
	}
	var enc []byte
	err := tx.QueryRow(ctx, q, s.instanceID, idx).Scan(&enc)
	if errors.Is(err, pgx.ErrNoRows) {
		return &contactRecord{JID: jid}, nil
	} else if err != nil {
		return nil, err
	}
	return s.decodeContact(idx, enc)
}

func (s *Store) decodeContact(idx, enc []byte) (*contactRecord, error) {
	pt, err := s.open(enc, "contacts", idx)
	if err != nil {
		return nil, err
	}
	var r contactRecord
	if err := json.Unmarshal(pt, &r); err != nil {
		return nil, fmt.Errorf("store: contato corrompido: %w", err)
	}
	r.found = true
	return &r, nil
}

func (s *Store) saveContactTx(ctx context.Context, tx pgx.Tx, idx []byte, r *contactRecord) error {
	pt, err := json.Marshal(r)
	if err != nil {
		return err
	}
	enc, err := s.seal(pt, "contacts", idx)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO wa.contacts (instance_id, tenant_id, jid_idx, contact_enc) VALUES ($1, $2, $3, $4)
		ON CONFLICT (instance_id, jid_idx) DO UPDATE SET contact_enc = excluded.contact_enc`,
		s.instanceID, s.tenantID, idx, enc)
	return err
}

// getContactLocked usa o cache; contactMu deve estar travado.
func (s *Store) getContactLocked(ctx context.Context, jid string) (*contactRecord, error) {
	if c, ok := s.contactCache[jid]; ok {
		return c, nil
	}
	idx, err := s.idx(idxJID, jid)
	if err != nil {
		return nil, err
	}
	var r *contactRecord
	err = s.read(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		r, err = s.loadContactTx(ctx, tx, jid, idx, false)
		return err
	})
	if err != nil {
		return nil, err
	}
	s.contactCache[jid] = r
	return r, nil
}

// updateContact faz leitura-modificação-escrita do registro no banco (com
// trava de linha) e atualiza o cache.
func (s *Store) updateContactLocked(ctx context.Context, jid string, mutate func(*contactRecord)) error {
	idx, err := s.idx(idxJID, jid)
	if err != nil {
		return err
	}
	var saved *contactRecord
	err = s.write(ctx, func(ctx context.Context, tx pgx.Tx) error {
		r, err := s.loadContactTx(ctx, tx, jid, idx, true)
		if err != nil {
			return err
		}
		mutate(r)
		if err := s.saveContactTx(ctx, tx, idx, r); err != nil {
			return err
		}
		r.found = true
		saved = r
		return nil
	})
	if err != nil {
		return err
	}
	s.contactCache[jid] = saved
	return nil
}

func (s *Store) PutPushName(ctx context.Context, user types.JID, pushName string) (bool, string, error) {
	s.contactMu.Lock()
	defer s.contactMu.Unlock()
	jid := user.String()
	cached, err := s.getContactLocked(ctx, jid)
	if err != nil {
		return false, "", err
	}
	if cached.PushName == pushName {
		return false, "", nil
	}
	previous := cached.PushName
	if err := s.updateContactLocked(ctx, jid, func(r *contactRecord) { r.PushName = pushName }); err != nil {
		return false, "", err
	}
	return true, previous, nil
}

func (s *Store) PutBusinessName(ctx context.Context, user types.JID, businessName string) (bool, string, error) {
	s.contactMu.Lock()
	defer s.contactMu.Unlock()
	jid := user.String()
	cached, err := s.getContactLocked(ctx, jid)
	if err != nil {
		return false, "", err
	}
	if cached.BusinessName == businessName {
		return false, "", nil
	}
	previous := cached.BusinessName
	if err := s.updateContactLocked(ctx, jid, func(r *contactRecord) { r.BusinessName = businessName }); err != nil {
		return false, "", err
	}
	return true, previous, nil
}

func (s *Store) PutContactName(ctx context.Context, user types.JID, firstName, fullName string) error {
	s.contactMu.Lock()
	defer s.contactMu.Unlock()
	jid := user.String()
	cached, err := s.getContactLocked(ctx, jid)
	if err != nil {
		return err
	}
	if cached.FirstName == firstName && cached.FullName == fullName {
		return nil
	}
	return s.updateContactLocked(ctx, jid, func(r *contactRecord) { r.FirstName, r.FullName = firstName, fullName })
}

const contactBatchSize = 300

// dedupFirst mantém a primeira ocorrência de cada JID, como o
// exslices.DeduplicateUnsortedOverwriteFunc usado pelo sqlstore.
func dedupFirst[T any](items []T, key func(T) types.JID) []T {
	seen := make(map[types.JID]bool, len(items))
	out := make([]T, 0, len(items))
	for _, it := range items {
		if k := key(it); !seen[k] {
			seen[k] = true
			out = append(out, it)
		}
	}
	return out
}

// bulkMergeContacts aplica mutate a vários contatos numa transação: carrega
// os existentes em lote, mescla e grava.
func (s *Store) bulkMergeContacts(ctx context.Context, jids []string, mutate func(i int, r *contactRecord)) error {
	return s.write(ctx, func(ctx context.Context, tx pgx.Tx) error {
		for start := 0; start < len(jids); start += contactBatchSize {
			end := min(start+contactBatchSize, len(jids))
			idxs := make([][]byte, end-start)
			for i := range idxs {
				var err error
				if idxs[i], err = s.idx(idxJID, jids[start+i]); err != nil {
					return err
				}
			}
			existing := make(map[string]*contactRecord, len(idxs))
			rows, err := tx.Query(ctx, `
				SELECT jid_idx, contact_enc FROM wa.contacts WHERE instance_id = $1 AND jid_idx = ANY($2::bytea[]) FOR UPDATE`,
				s.instanceID, idxs)
			if err != nil {
				return err
			}
			for rows.Next() {
				var idx, enc []byte
				if err := rows.Scan(&idx, &enc); err != nil {
					rows.Close()
					return err
				}
				r, err := s.decodeContact(idx, enc)
				if err != nil {
					rows.Close()
					return err
				}
				existing[string(idx)] = r
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return err
			}
			for i, idx := range idxs {
				r, ok := existing[string(idx)]
				if !ok {
					r = &contactRecord{JID: jids[start+i]}
				}
				mutate(start+i, r)
				if err := s.saveContactTx(ctx, tx, idx, r); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

func (s *Store) PutAllContactNames(ctx context.Context, contacts []wastore.ContactEntry) error {
	if len(contacts) == 0 {
		return nil
	}
	orig := len(contacts)
	contacts = dedupFirst(contacts, func(c wastore.ContactEntry) types.JID { return c.JID })
	if orig != len(contacts) {
		s.log.Warn("contatos duplicados em PutAllContactNames", "quantidade", orig-len(contacts))
	}
	jids := make([]string, len(contacts))
	for i, c := range contacts {
		jids[i] = c.JID.String()
	}
	err := s.bulkMergeContacts(ctx, jids, func(i int, r *contactRecord) {
		r.FirstName, r.FullName = contacts[i].FirstName, contacts[i].FullName
	})
	if err != nil {
		return err
	}
	s.contactMu.Lock()
	s.contactCache = map[string]*contactRecord{}
	s.contactMu.Unlock()
	return nil
}

func (s *Store) PutManyRedactedPhones(ctx context.Context, entries []wastore.RedactedPhoneEntry) error {
	if len(entries) == 0 {
		return nil
	}
	orig := len(entries)
	entries = dedupFirst(entries, func(e wastore.RedactedPhoneEntry) types.JID { return e.JID })
	if orig != len(entries) {
		s.log.Warn("contatos duplicados em PutManyRedactedPhones", "quantidade", orig-len(entries))
	}
	jids := make([]string, len(entries))
	for i, e := range entries {
		jids[i] = e.JID.String()
	}
	if err := s.bulkMergeContacts(ctx, jids, func(i int, r *contactRecord) { r.RedactedPhone = entries[i].RedactedPhone }); err != nil {
		return err
	}
	s.contactMu.Lock()
	for _, e := range entries {
		if c, ok := s.contactCache[e.JID.String()]; ok && c.RedactedPhone == e.RedactedPhone {
			continue
		}
		delete(s.contactCache, e.JID.String())
	}
	s.contactMu.Unlock()
	return nil
}

func (s *Store) GetContact(ctx context.Context, user types.JID) (types.ContactInfo, error) {
	s.contactMu.Lock()
	defer s.contactMu.Unlock()
	r, err := s.getContactLocked(ctx, user.String())
	if err != nil {
		return types.ContactInfo{}, err
	}
	return r.info(), nil
}

func (s *Store) GetAllContacts(ctx context.Context) (map[types.JID]types.ContactInfo, error) {
	s.contactMu.Lock()
	defer s.contactMu.Unlock()
	out := make(map[types.JID]types.ContactInfo)
	err := s.read(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT jid_idx, contact_enc FROM wa.contacts WHERE instance_id = $1`, s.instanceID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var idx, enc []byte
			if err := rows.Scan(&idx, &enc); err != nil {
				return err
			}
			r, err := s.decodeContact(idx, enc)
			if err != nil {
				return err
			}
			jid, err := types.ParseJID(r.JID)
			if err != nil {
				return fmt.Errorf("store: JID de contato inválido: %w", err)
			}
			out[jid] = r.info()
			s.contactCache[r.JID] = r
		}
		return rows.Err()
	})
	return out, err
}

// ---------------------------------------------------------------------------
// ChatSettingsStore. As configurações não são sensíveis; o JID da conversa é.

func (s *Store) putChatSetting(ctx context.Context, chat types.JID, column string, value any) error {
	if !slices.Contains([]string{"muted_until", "pinned", "archived", "wasa_root_secret_id"}, column) {
		return fmt.Errorf("store: coluna de configuração desconhecida %q", column)
	}
	idx, err := s.idx(idxJID, chat.String())
	if err != nil {
		return err
	}
	return s.write(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, fmt.Sprintf(`
			INSERT INTO wa.chat_settings (instance_id, tenant_id, chat_idx, %[1]s) VALUES ($1, $2, $3, $4)
			ON CONFLICT (instance_id, chat_idx) DO UPDATE SET %[1]s = excluded.%[1]s`, column),
			s.instanceID, s.tenantID, idx, value)
		return err
	})
}

func (s *Store) PutMutedUntil(ctx context.Context, chat types.JID, mutedUntil time.Time) error {
	var v int64
	switch {
	case mutedUntil.Equal(wastore.MutedForever):
		v = -1
	case !mutedUntil.IsZero():
		v = mutedUntil.Unix()
	}
	return s.putChatSetting(ctx, chat, "muted_until", v)
}

func (s *Store) PutPinned(ctx context.Context, chat types.JID, pinned bool) error {
	return s.putChatSetting(ctx, chat, "pinned", pinned)
}

func (s *Store) PutArchived(ctx context.Context, chat types.JID, archived bool) error {
	return s.putChatSetting(ctx, chat, "archived", archived)
}

func (s *Store) PutWASARootSecretID(ctx context.Context, chat types.JID, id types.MessageID) error {
	return s.putChatSetting(ctx, chat, "wasa_root_secret_id", id)
}

func (s *Store) GetWASARootSecretID(ctx context.Context, chat types.JID) (types.MessageID, error) {
	idx, err := s.idx(idxJID, chat.String())
	if err != nil {
		return "", err
	}
	var id string
	err = s.read(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT wasa_root_secret_id FROM wa.chat_settings WHERE instance_id = $1 AND chat_idx = $2`,
			s.instanceID, idx).Scan(&id)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return id, err
}

func (s *Store) GetChatSettings(ctx context.Context, chat types.JID) (types.LocalChatSettings, error) {
	var settings types.LocalChatSettings
	idx, err := s.idx(idxJID, chat.String())
	if err != nil {
		return settings, err
	}
	var muted int64
	err = s.read(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT muted_until, pinned, archived FROM wa.chat_settings WHERE instance_id = $1 AND chat_idx = $2`,
			s.instanceID, idx).Scan(&muted, &settings.Pinned, &settings.Archived)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return settings, nil
	} else if err != nil {
		return settings, err
	}
	settings.Found = true
	if muted < 0 {
		settings.MutedUntil = wastore.MutedForever
	} else if muted > 0 {
		settings.MutedUntil = time.Unix(muted, 0)
	}
	return settings, nil
}
