package passkey

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ErrDuplicate: a credencial já está cadastrada.
var ErrDuplicate = errors.New("passkey: credencial já cadastrada")

// DB é o mínimo que o armazenamento Postgres precisa (pool ou transação).
type DB interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// PGCredentials implementa Credentials sobre ident.webauthn_credentials.
type PGCredentials struct{ db DB }

// NewPGCredentials cria o armazenamento Postgres.
func NewPGCredentials(db DB) *PGCredentials { return &PGCredentials{db: db} }

const storedCols = `user_id, credential, label, created_at, last_used_at`

func scanStored(row pgx.Row) (Stored, error) {
	var st Stored
	var raw []byte
	var lastUsed *time.Time
	if err := row.Scan(&st.UserID, &raw, &st.Label, &st.CreatedAt, &lastUsed); err != nil {
		return Stored{}, err
	}
	if err := json.Unmarshal(raw, &st.Credential); err != nil {
		return Stored{}, fmt.Errorf("passkey: credencial corrompida: %w", err)
	}
	if lastUsed != nil {
		st.LastUsedAt = *lastUsed
	}
	return st, nil
}

func (p *PGCredentials) ListByUser(ctx context.Context, userID uuid.UUID) ([]Stored, error) {
	rows, err := p.db.Query(ctx, `SELECT `+storedCols+` FROM ident.webauthn_credentials WHERE user_id = $1 ORDER BY created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Stored
	for rows.Next() {
		st, err := scanStored(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

func (p *PGCredentials) Add(ctx context.Context, userID uuid.UUID, c webauthn.Credential, label string, now time.Time) error {
	raw, err := json.Marshal(c)
	if err != nil {
		return err
	}
	// ON CONFLICT DO NOTHING: duplicata não aborta a transação de quem chama.
	tag, err := p.db.Exec(ctx, `
		INSERT INTO ident.webauthn_credentials (credential_id, user_id, credential, label, created_at)
		VALUES ($1, $2, $3, $4, $5) ON CONFLICT (credential_id) DO NOTHING`,
		c.ID, userID, raw, label, now)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrDuplicate
	}
	return nil
}

func (p *PGCredentials) Find(ctx context.Context, id []byte) (Stored, error) {
	st, err := scanStored(p.db.QueryRow(ctx, `SELECT `+storedCols+` FROM ident.webauthn_credentials WHERE credential_id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Stored{}, ErrNotFound
	}
	return st, err
}

func (p *PGCredentials) Update(ctx context.Context, id []byte, c webauthn.Credential, usedAt time.Time) error {
	raw, err := json.Marshal(c)
	if err != nil {
		return err
	}
	tag, err := p.db.Exec(ctx, `UPDATE ident.webauthn_credentials SET credential = $2, last_used_at = $3 WHERE credential_id = $1`,
		id, raw, usedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *PGCredentials) Delete(ctx context.Context, userID uuid.UUID, id []byte) error {
	tag, err := p.db.Exec(ctx, `DELETE FROM ident.webauthn_credentials WHERE credential_id = $1 AND user_id = $2`, id, userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
