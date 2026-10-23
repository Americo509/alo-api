package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Americo509/alo-api/internal/clock"
)

// Sealer cifra o detalhe do evento (IP, User-Agent, Meta).
type Sealer interface {
	Seal(plaintext, aad []byte) ([]byte, error)
	Open(sealed, aad []byte) ([]byte, error)
}

// DB é o mínimo que o armazenamento Postgres precisa.
type DB interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// PG implementa Recorder e Reader sobre ident.auth_events.
type PG struct {
	db     DB
	sealer Sealer
	clock  clock.Clock
}

// NewPG cria o armazenamento. Para DeleteOlderThan, passe um DB conectado como
// membro da role app_retention (a app_rw não tem DELETE).
func NewPG(db DB, sealer Sealer, clk clock.Clock) (*PG, error) {
	if db == nil || sealer == nil || clk == nil {
		return nil, errors.New("audit: dependências obrigatórias ausentes")
	}
	return &PG{db: db, sealer: sealer, clock: clk}, nil
}

type detail struct {
	IP   string            `json:"ip,omitempty"`
	UA   string            `json:"ua,omitempty"`
	Meta map[string]string `json:"m,omitempty"`
}

func aad(id uuid.UUID) []byte { return append([]byte("auth-event:"), id[:]...) }

func (p *PG) Record(ctx context.Context, e Event) error {
	e = Sanitize(e)
	id := uuid.New()
	raw, err := json.Marshal(detail{IP: e.IP, UA: e.UserAgent, Meta: e.Meta})
	if err != nil {
		return err
	}
	enc, err := p.sealer.Seal(raw, aad(id))
	if err != nil {
		return fmt.Errorf("audit: cifrar evento: %w", err)
	}
	var uid *uuid.UUID
	if e.UserID != uuid.Nil {
		uid = &e.UserID
	}
	_, err = p.db.Exec(ctx, `
		INSERT INTO ident.auth_events (id, user_id, event, at, detail_enc) VALUES ($1, $2, $3, $4, $5)`,
		id, uid, string(e.Type), p.clock.Now(), enc)
	return err
}

func (p *PG) RecentByUser(ctx context.Context, userID uuid.UUID, limit int) ([]Event, error) {
	if limit < 1 || limit > 200 {
		limit = 50
	}
	rows, err := p.db.Query(ctx, `
		SELECT id, event, at, detail_enc FROM ident.auth_events
		WHERE user_id = $1 ORDER BY at DESC LIMIT $2`, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var id uuid.UUID
		var typ string
		var at time.Time
		var enc []byte
		if err := rows.Scan(&id, &typ, &at, &enc); err != nil {
			return nil, err
		}
		raw, err := p.sealer.Open(enc, aad(id))
		if err != nil {
			return nil, fmt.Errorf("audit: decifrar evento: %w", err)
		}
		var d detail
		if err := json.Unmarshal(raw, &d); err != nil {
			return nil, err
		}
		out = append(out, Event{Type: Type(typ), UserID: userID, IP: d.IP, UserAgent: d.UA, Meta: d.Meta, At: at})
	}
	return out, rows.Err()
}

func (p *PG) DeleteOlderThan(ctx context.Context, cutoff time.Time) (int64, error) {
	tag, err := p.db.Exec(ctx, `DELETE FROM ident.auth_events WHERE at < $1`, cutoff)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

var (
	_ Recorder = (*PG)(nil)
	_ Reader   = (*PG)(nil)
	_ Recorder = (*Memory)(nil)
	_ Reader   = (*Memory)(nil)
)
