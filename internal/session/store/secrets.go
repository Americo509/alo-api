package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	wastore "go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
)

// altJIDs devolve o JID e, se existir, o equivalente LID↔telefone pelo mapa
// desta instância. withSelfForOthers replica o "ELSE $2" do sqlstore em
// privacy tokens (servidores fora de lid/s.whatsapp.net comparam consigo).
func (s *Store) altJIDs(ctx context.Context, jid types.JID) ([]types.JID, error) {
	out := []types.JID{jid}
	var alt types.JID
	var err error
	switch jid.Server {
	case types.HiddenUserServer:
		alt, err = s.lids.GetPNForLID(ctx, jid)
	case types.DefaultUserServer:
		alt, err = s.lids.GetLIDForPN(ctx, jid)
	default:
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	if !alt.IsEmpty() {
		// O sqlstore compara a forma sem aparelho (user@server).
		out = append(out, types.JID{User: alt.User, Server: alt.Server})
	}
	return out, nil
}

func (s *Store) jidIdxs(jids []types.JID) ([][]byte, error) {
	out := make([][]byte, len(jids))
	for i, j := range jids {
		var err error
		if out[i], err = s.idx(idxJID, j.String()); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// MsgSecretStore

type msgSecretRecord struct {
	Secret []byte `json:"s"`
	Sender string `json:"r"`
}

func (s *Store) putMessageSecretTx(ctx context.Context, tx pgx.Tx, chat, sender types.JID, id types.MessageID, secret []byte) error {
	chatJID, senderJID := chat.ToNonAD(), sender.ToNonAD()
	ci, err := s.idx(idxJID, chatJID.String())
	if err != nil {
		return err
	}
	si, err := s.idx(idxJID, senderJID.String())
	if err != nil {
		return err
	}
	// Serializado só para ser cifrado na linha seguinte; o buffer é zerado.
	pt, err := json.Marshal(msgSecretRecord{Secret: secret, Sender: senderJID.String()}) //nolint:gosec // G117: vai direto para seal
	if err != nil {
		return err
	}
	enc, err := s.seal(pt, "message_secrets", ci, si, []byte(id))
	clear(pt)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO wa.message_secrets (instance_id, tenant_id, chat_idx, sender_idx, message_id, secret_enc)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (instance_id, chat_idx, sender_idx, message_id) DO NOTHING`,
		s.instanceID, s.tenantID, ci, si, id, enc)
	return err
}

func (s *Store) PutMessageSecrets(ctx context.Context, inserts []wastore.MessageSecretInsert) error {
	if len(inserts) == 0 {
		return nil
	}
	return s.write(ctx, func(ctx context.Context, tx pgx.Tx) error {
		for _, in := range inserts {
			if in.Chat.IsEmpty() || in.Sender.IsEmpty() || in.ID == "" || len(in.Secret) == 0 {
				continue
			}
			if err := s.putMessageSecretTx(ctx, tx, in.Chat, in.Sender, in.ID, in.Secret); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) PutMessageSecret(ctx context.Context, chat, sender types.JID, id types.MessageID, secret []byte) error {
	return s.write(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return s.putMessageSecretTx(ctx, tx, chat, sender, id, secret)
	})
}

// GetMessageSecret procura pelo chat e pelo remetente, aceitando também o
// equivalente LID↔telefone de cada um.
func (s *Store) GetMessageSecret(ctx context.Context, chat, sender types.JID, id types.MessageID) ([]byte, types.JID, error) {
	chats, err := s.altJIDs(ctx, chat.ToNonAD())
	if err != nil {
		return nil, types.JID{}, err
	}
	senders, err := s.altJIDs(ctx, sender.ToNonAD())
	if err != nil {
		return nil, types.JID{}, err
	}
	cis, err := s.jidIdxs(chats)
	if err != nil {
		return nil, types.JID{}, err
	}
	sis, err := s.jidIdxs(senders)
	if err != nil {
		return nil, types.JID{}, err
	}
	var ci, si, enc []byte
	err = s.read(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT chat_idx, sender_idx, secret_enc FROM wa.message_secrets
			WHERE instance_id = $1 AND chat_idx = ANY($2::bytea[]) AND sender_idx = ANY($3::bytea[]) AND message_id = $4
			LIMIT 1`,
			s.instanceID, cis, sis, id).Scan(&ci, &si, &enc)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, types.JID{}, nil
	} else if err != nil {
		return nil, types.JID{}, err
	}
	pt, err := s.open(enc, "message_secrets", ci, si, []byte(id))
	if err != nil {
		return nil, types.JID{}, err
	}
	var r msgSecretRecord
	if err := json.Unmarshal(pt, &r); err != nil {
		return nil, types.JID{}, fmt.Errorf("store: segredo de mensagem corrompido: %w", err)
	}
	realSender, err := types.ParseJID(r.Sender)
	if err != nil {
		return nil, types.JID{}, fmt.Errorf("store: remetente inválido: %w", err)
	}
	return r.Secret, realSender, nil
}

// ---------------------------------------------------------------------------
// PrivacyTokenStore

func (s *Store) PutPrivacyTokens(ctx context.Context, tokens ...wastore.PrivacyToken) error {
	if len(tokens) == 0 {
		return nil
	}
	return s.write(ctx, func(ctx context.Context, tx pgx.Tx) error {
		for _, t := range tokens {
			ti, err := s.idx(idxJID, t.User.ToNonAD().String())
			if err != nil {
				return err
			}
			enc, err := s.seal(t.Token, "privacy_tokens", ti)
			if err != nil {
				return err
			}
			var senderTS *int64
			if !t.SenderTimestamp.IsZero() {
				v := t.SenderTimestamp.Unix()
				senderTS = &v
			}
			_, err = tx.Exec(ctx, `
				INSERT INTO wa.privacy_tokens (instance_id, tenant_id, their_idx, token_enc, ts, sender_ts)
				VALUES ($1, $2, $3, $4, $5, $6)
				ON CONFLICT (instance_id, their_idx) DO UPDATE SET
					token_enc = excluded.token_enc,
					ts = excluded.ts,
					sender_ts = COALESCE(excluded.sender_ts, wa.privacy_tokens.sender_ts)
				WHERE excluded.ts >= wa.privacy_tokens.ts`,
				s.instanceID, s.tenantID, ti, enc, t.Timestamp.Unix(), senderTS)
			if err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) GetPrivacyToken(ctx context.Context, user types.JID) (*wastore.PrivacyToken, error) {
	token := wastore.PrivacyToken{User: user.ToNonAD()}
	alts, err := s.altJIDs(ctx, token.User)
	if err != nil {
		return nil, err
	}
	idxs, err := s.jidIdxs(alts)
	if err != nil {
		return nil, err
	}
	var ti, enc []byte
	var ts int64
	var senderTS *int64
	err = s.read(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT their_idx, token_enc, ts, sender_ts FROM wa.privacy_tokens
			WHERE instance_id = $1 AND their_idx = ANY($2::bytea[])
			ORDER BY ts DESC LIMIT 1`,
			s.instanceID, idxs).Scan(&ti, &enc, &ts, &senderTS)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	if token.Token, err = s.open(enc, "privacy_tokens", ti); err != nil {
		return nil, err
	}
	token.Timestamp = time.Unix(ts, 0)
	if senderTS != nil {
		token.SenderTimestamp = time.Unix(*senderTS, 0)
	}
	return &token, nil
}

func (s *Store) DeleteExpiredPrivacyTokens(ctx context.Context, cutoff time.Time) (int64, error) {
	var n int64
	err := s.write(ctx, func(ctx context.Context, tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM wa.privacy_tokens WHERE instance_id = $1 AND ts < $2`, s.instanceID, cutoff.Unix())
		n = tag.RowsAffected()
		return err
	})
	return n, err
}

// ---------------------------------------------------------------------------
// NCTSaltStore

func (s *Store) PutNCTSalt(ctx context.Context, salt []byte) error {
	enc, err := s.seal(salt, "nct_salt")
	if err != nil {
		return err
	}
	return s.write(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO wa.nct_salt (instance_id, tenant_id, salt_enc) VALUES ($1, $2, $3)
			ON CONFLICT (instance_id) DO UPDATE SET salt_enc = excluded.salt_enc`,
			s.instanceID, s.tenantID, enc)
		return err
	})
}

func (s *Store) GetNCTSalt(ctx context.Context) ([]byte, error) {
	var enc []byte
	err := s.read(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT salt_enc FROM wa.nct_salt WHERE instance_id = $1`, s.instanceID).Scan(&enc)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return s.open(enc, "nct_salt")
}

func (s *Store) DeleteNCTSalt(ctx context.Context) error {
	return s.write(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM wa.nct_salt WHERE instance_id = $1`, s.instanceID)
		return err
	})
}
