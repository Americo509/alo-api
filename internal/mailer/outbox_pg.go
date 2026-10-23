package mailer

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// DB é o mínimo que a fila Postgres precisa (pool ou transação).
type DB interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// PGOutbox implementa Outbox sobre ident.email_outbox.
type PGOutbox struct{ db DB }

// NewPGOutbox cria a fila Postgres.
func NewPGOutbox(db DB) *PGOutbox { return &PGOutbox{db: db} }

func (p *PGOutbox) Enqueue(ctx context.Context, it Item, availableAt time.Time) error {
	_, err := p.db.Exec(ctx, `
		INSERT INTO ident.email_outbox (id, kind, payload_enc, available_at, expires_at)
		VALUES ($1, $2, $3, $4, $5)`,
		it.ID, string(it.Kind), it.Payload, availableAt, it.ExpiresAt)
	if err != nil {
		return fmt.Errorf("mailer: gravar na fila: %w", err)
	}
	return nil
}

// Claim usa FOR UPDATE SKIP LOCKED: vários despachantes podem rodar ao mesmo
// tempo sem pegar o mesmo item; o lease cobre a queda de um despachante no meio
// do envio.
func (p *PGOutbox) Claim(ctx context.Context, now time.Time, limit int, lease time.Duration) ([]Item, error) {
	rows, err := p.db.Query(ctx, `
		WITH c AS (
		  SELECT id FROM ident.email_outbox
		  WHERE dead = false AND available_at <= $1 AND (locked_until IS NULL OR locked_until <= $1)
		  ORDER BY available_at
		  LIMIT $2
		  FOR UPDATE SKIP LOCKED
		)
		UPDATE ident.email_outbox o
		SET attempts = o.attempts + 1, locked_until = $3
		FROM c WHERE o.id = c.id
		RETURNING o.id, o.kind, o.payload_enc, o.attempts, o.expires_at`,
		now, limit, now.Add(lease))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Item
	for rows.Next() {
		var it Item
		var kind string
		if err := rows.Scan(&it.ID, &kind, &it.Payload, &it.Attempts, &it.ExpiresAt); err != nil {
			return nil, err
		}
		it.Kind = Kind(kind)
		out = append(out, it)
	}
	return out, rows.Err()
}

func (p *PGOutbox) Done(ctx context.Context, id uuid.UUID) error {
	_, err := p.db.Exec(ctx, `DELETE FROM ident.email_outbox WHERE id = $1`, id)
	return err
}

func (p *PGOutbox) Retry(ctx context.Context, id uuid.UUID, next time.Time, errClass string) error {
	_, err := p.db.Exec(ctx, `
		UPDATE ident.email_outbox SET available_at = $2, locked_until = NULL, last_error = $3 WHERE id = $1`,
		id, next, truncate(errClass, 40))
	return err
}

func (p *PGOutbox) Dead(ctx context.Context, id uuid.UUID, now time.Time, errClass string) error {
	_, err := p.db.Exec(ctx, `
		UPDATE ident.email_outbox
		SET dead = true, dead_at = $2, payload_enc = NULL, locked_until = NULL, last_error = $3
		WHERE id = $1`, id, now, truncate(errClass, 40))
	return err
}

func (p *PGOutbox) PurgeDead(ctx context.Context, olderThan time.Time) (int64, error) {
	tag, err := p.db.Exec(ctx, `DELETE FROM ident.email_outbox WHERE dead = true AND dead_at < $1`, olderThan)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
