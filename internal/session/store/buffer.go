package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	wastore "go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
)

// Prazos do protocolo (mesmos do sqlstore): o servidor do WhatsApp só guarda
// eventos por 14 dias; mensagens enviadas ficam disponíveis para reenvio por 7.
const (
	eventBufferRetention = 14 * 24 * time.Hour
	retryBufferRetention = 7 * 24 * time.Hour
)

// ---------------------------------------------------------------------------
// EventBuffer: mensagens recebidas já decifradas. Conteúdo sempre cifrado em
// repouso e apagado assim que processado (ClearBufferedEventPlaintext).

func (s *Store) GetBufferedEvent(ctx context.Context, hash [32]byte) (*wastore.BufferedEvent, error) {
	var enc []byte
	var serverTS, insertMS int64
	err := s.read(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT plaintext_enc, server_ts, insert_ts_ms FROM wa.event_buffer WHERE instance_id = $1 AND ciphertext_hash = $2`,
			s.instanceID, hash[:]).Scan(&enc, &serverTS, &insertMS)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	buf := &wastore.BufferedEvent{ServerTime: time.Unix(serverTS, 0), InsertTime: time.UnixMilli(insertMS)}
	if enc != nil {
		if buf.Plaintext, err = s.open(enc, "event_buffer", hash[:]); err != nil {
			return nil, err
		}
	}
	return buf, nil
}

func (s *Store) PutBufferedEvent(ctx context.Context, hash [32]byte, plaintext []byte, serverTimestamp time.Time) error {
	var enc []byte
	if plaintext != nil {
		var err error
		if enc, err = s.seal(plaintext, "event_buffer", hash[:]); err != nil {
			return err
		}
	}
	return s.write(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO wa.event_buffer (instance_id, tenant_id, ciphertext_hash, plaintext_enc, server_ts, insert_ts_ms)
			VALUES ($1, $2, $3, $4, $5, $6)`,
			s.instanceID, s.tenantID, hash[:], enc, serverTimestamp.Unix(), s.clock.Now().UnixMilli())
		return err
	})
}

// DoDecryptionTxn: decifrar a mensagem e gravar o buffer acontecem juntos ou
// não acontecem.
func (s *Store) DoDecryptionTxn(ctx context.Context, fn func(context.Context) error) error {
	return s.DoTxn(ctx, fn)
}

func (s *Store) ClearBufferedEventPlaintext(ctx context.Context, hash [32]byte) error {
	return s.write(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE wa.event_buffer SET plaintext_enc = NULL WHERE instance_id = $1 AND ciphertext_hash = $2`,
			s.instanceID, hash[:])
		return err
	})
}

func (s *Store) DeleteOldBufferedHashes(ctx context.Context) error {
	cutoff := s.clock.Now().Add(-eventBufferRetention).UnixMilli()
	return s.write(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM wa.event_buffer WHERE instance_id = $1 AND insert_ts_ms < $2`, s.instanceID, cutoff)
		return err
	})
}

// ---------------------------------------------------------------------------
// Retry buffer: mensagens enviadas, para reenvio quando o destinatário pede.

// GetOutgoingEvent devolve erro (ErrNotFound) quando não há registro: o
// whatsmeow trata qualquer erro como "não dá para reenviar".
func (s *Store) GetOutgoingEvent(ctx context.Context, chatJID, altChatJID types.JID, id types.MessageID) (string, []byte, error) {
	idxs, err := s.jidIdxs([]types.JID{chatJID, altChatJID})
	if err != nil {
		return "", nil, err
	}
	var ci, enc []byte
	var format string
	err = s.read(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT chat_idx, format, plaintext_enc FROM wa.retry_buffer
			WHERE instance_id = $1 AND chat_idx = ANY($2::bytea[]) AND message_id = $3 LIMIT 1`,
			s.instanceID, idxs, id).Scan(&ci, &format, &enc)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil, fmt.Errorf("%w: mensagem para reenvio", ErrNotFound)
	} else if err != nil {
		return "", nil, err
	}
	pt, err := s.open(enc, "retry_buffer", ci, []byte(id))
	if err != nil {
		return "", nil, err
	}
	return format, pt, nil
}

func (s *Store) AddOutgoingEvent(ctx context.Context, chatJID types.JID, id types.MessageID, format string, plaintext []byte) error {
	ci, err := s.idx(idxJID, chatJID.String())
	if err != nil {
		return err
	}
	enc, err := s.seal(plaintext, "retry_buffer", ci, []byte(id))
	if err != nil {
		return err
	}
	return s.write(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO wa.retry_buffer (instance_id, tenant_id, chat_idx, message_id, format, plaintext_enc, ts_ms)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (instance_id, chat_idx, message_id) DO UPDATE
				SET format = excluded.format, plaintext_enc = excluded.plaintext_enc, ts_ms = excluded.ts_ms`,
			s.instanceID, s.tenantID, ci, id, format, enc, s.clock.Now().UnixMilli())
		return err
	})
}

func (s *Store) DeleteOldOutgoingEvents(ctx context.Context) error {
	cutoff := s.clock.Now().Add(-retryBufferRetention).UnixMilli()
	return s.write(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM wa.retry_buffer WHERE instance_id = $1 AND ts_ms < $2`, s.instanceID, cutoff)
		return err
	})
}
