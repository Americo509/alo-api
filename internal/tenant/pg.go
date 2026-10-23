package tenant

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/Americo509/alo-api/internal/identity"
	"github.com/Americo509/alo-api/internal/storage/postgres"
)

// DB é o que o PG precisa do pool.
type DB interface {
	postgres.Beginner
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// PG é o Store em Postgres. core.tenants tem RLS: toda leitura/escrita nela
// acontece numa transação com app.tenant_id definido (WithTenantTx). As
// tabelas de ident (memberships, users) não têm RLS: a autorização é feita
// pelo Service.
type PG struct{ db DB }

// NewPG cria o Store.
func NewPG(db DB) *PG { return &PG{db: db} }

const (
	pgUniqueViolation = "23505"
	pgFKViolation     = "23503"
)

func pgCode(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}

// Create implementa Store.
func (p *PG) Create(ctx context.Context, t Tenant) error {
	return postgres.WithTenantTx(ctx, p.db, t.ID, pgx.TxOptions{}, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO core.tenants (id, name, status, created_by, created_at) VALUES ($1, $2, $3, $4, $5)`,
			t.ID, t.Name, string(t.Status), t.CreatedBy, t.CreatedAt); err != nil {
			return fmt.Errorf("tenant: criar: %w", err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO ident.memberships (user_id, tenant_id, role) VALUES ($1, $2, $3)`,
			t.CreatedBy, t.ID, string(identity.RoleOwner)); err != nil {
			return fmt.Errorf("tenant: vincular dono: %w", err)
		}
		return nil
	})
}

// Get implementa Store.
func (p *PG) Get(ctx context.Context, id uuid.UUID) (Tenant, error) {
	var t Tenant
	err := postgres.WithTenantTx(ctx, p.db, id, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		return scanTenant(tx.QueryRow(ctx,
			`SELECT id, name, status, COALESCE(created_by, '00000000-0000-0000-0000-000000000000'), created_at FROM core.tenants WHERE id = $1`, id), &t)
	})
	return t, err
}

func scanTenant(row pgx.Row, t *Tenant) error {
	var status string
	if err := row.Scan(&t.ID, &t.Name, &status, &t.CreatedBy, &t.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	t.Status = Status(status)
	return nil
}

func (p *PG) update(ctx context.Context, id uuid.UUID, sql string, arg any) error {
	return postgres.WithTenantTx(ctx, p.db, id, pgx.TxOptions{}, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, sql, id, arg)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// SetStatus implementa Store.
func (p *PG) SetStatus(ctx context.Context, id uuid.UUID, s Status) error {
	return p.update(ctx, id, `UPDATE core.tenants SET status = $2 WHERE id = $1`, string(s))
}

// Rename implementa Store.
func (p *PG) Rename(ctx context.Context, id uuid.UUID, name string) error {
	return p.update(ctx, id, `UPDATE core.tenants SET name = $2 WHERE id = $1`, name)
}

// OwnedCount implementa Store.
func (p *PG) OwnedCount(ctx context.Context, userID uuid.UUID) (int, error) {
	var n int
	err := p.db.QueryRow(ctx, `SELECT count(*) FROM ident.memberships WHERE user_id = $1 AND role = 'dono'`, userID).Scan(&n)
	return n, err
}

const memberCols = `m.user_id, m.tenant_id, m.role, u.email, u.display_name, m.created_at`

func scanMember(row pgx.Row) (Member, error) {
	var m Member
	var role string
	if err := row.Scan(&m.UserID, &m.TenantID, &role, &m.Email, &m.DisplayName, &m.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Member{}, ErrNotFound
		}
		return Member{}, err
	}
	m.Role = identity.Role(role)
	return m, nil
}

// Member implementa Store.
func (p *PG) Member(ctx context.Context, tenantID, userID uuid.UUID) (Member, error) {
	return scanMember(p.db.QueryRow(ctx,
		`SELECT `+memberCols+` FROM ident.memberships m JOIN ident.users u ON u.id = m.user_id
		 WHERE m.tenant_id = $1 AND m.user_id = $2`, tenantID, userID))
}

// Members implementa Store.
func (p *PG) Members(ctx context.Context, tenantID uuid.UUID) ([]Member, error) {
	rows, err := p.db.Query(ctx,
		`SELECT `+memberCols+` FROM ident.memberships m JOIN ident.users u ON u.id = m.user_id
		 WHERE m.tenant_id = $1 ORDER BY m.created_at, m.user_id`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Member
	for rows.Next() {
		m, err := scanMember(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// MembershipsOf implementa Store. core.tenants tem RLS, então o nome de cada
// tenant é lido na transação dele (um usuário tem poucos tenants).
func (p *PG) MembershipsOf(ctx context.Context, userID uuid.UUID) ([]Membership, error) {
	rows, err := p.db.Query(ctx,
		`SELECT tenant_id, role FROM ident.memberships WHERE user_id = $1 ORDER BY created_at, tenant_id`, userID)
	if err != nil {
		return nil, err
	}
	type pair struct {
		id   uuid.UUID
		role identity.Role
	}
	var ps []pair
	for rows.Next() {
		var x pair
		var role string
		if err := rows.Scan(&x.id, &role); err != nil {
			rows.Close()
			return nil, err
		}
		x.role = identity.Role(role)
		ps = append(ps, x)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]Membership, 0, len(ps))
	for _, x := range ps {
		t, err := p.Get(ctx, x.id)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, Membership{Tenant: t, Role: x.role})
	}
	return out, nil
}

// AddMember implementa Store.
func (p *PG) AddMember(ctx context.Context, tenantID, userID uuid.UUID, role identity.Role) error {
	return postgres.WithTenantTx(ctx, p.db, tenantID, pgx.TxOptions{}, func(tx pgx.Tx) error {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM core.tenants WHERE id = $1)`, tenantID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return ErrNotFound
		}
		_, err := tx.Exec(ctx,
			`INSERT INTO ident.memberships (user_id, tenant_id, role) VALUES ($1, $2, $3)`, userID, tenantID, string(role))
		switch pgCode(err) {
		case "":
			return err
		case pgUniqueViolation:
			return ErrAlreadyMember
		case pgFKViolation:
			return ErrUserNotActive
		}
		return err
	})
}

// lockTenant serializa as mudanças de membros de um tenant: todas as
// operações travam a linha do tenant primeiro, na mesma ordem, o que evita
// deadlock e torna a contagem de donos confiável.
func lockTenant(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID) error {
	var id uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT id FROM core.tenants WHERE id = $1 FOR UPDATE`, tenantID).Scan(&id); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	return nil
}

func currentRole(ctx context.Context, tx pgx.Tx, tenantID, userID uuid.UUID) (identity.Role, error) {
	var role string
	err := tx.QueryRow(ctx,
		`SELECT role FROM ident.memberships WHERE tenant_id = $1 AND user_id = $2 FOR UPDATE`, tenantID, userID).Scan(&role)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	return identity.Role(role), err
}

func ownerCount(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID) (int, error) {
	var n int
	err := tx.QueryRow(ctx, `SELECT count(*) FROM ident.memberships WHERE tenant_id = $1 AND role = 'dono'`, tenantID).Scan(&n)
	return n, err
}

// SetRole implementa Store.
func (p *PG) SetRole(ctx context.Context, tenantID, userID uuid.UUID, expect, role identity.Role) error {
	return postgres.WithTenantTx(ctx, p.db, tenantID, pgx.TxOptions{}, func(tx pgx.Tx) error {
		if err := lockTenant(ctx, tx, tenantID); err != nil {
			return err
		}
		cur, err := currentRole(ctx, tx, tenantID, userID)
		if err != nil {
			return err
		}
		if cur != expect {
			return ErrStale
		}
		if cur == identity.RoleOwner && role != identity.RoleOwner {
			n, err := ownerCount(ctx, tx, tenantID)
			if err != nil {
				return err
			}
			if n <= 1 {
				return ErrLastOwner
			}
		}
		_, err = tx.Exec(ctx, `UPDATE ident.memberships SET role = $3 WHERE tenant_id = $1 AND user_id = $2`,
			tenantID, userID, string(role))
		return err
	})
}

// RemoveMember implementa Store.
func (p *PG) RemoveMember(ctx context.Context, tenantID, userID uuid.UUID) error {
	return postgres.WithTenantTx(ctx, p.db, tenantID, pgx.TxOptions{}, func(tx pgx.Tx) error {
		if err := lockTenant(ctx, tx, tenantID); err != nil {
			return err
		}
		cur, err := currentRole(ctx, tx, tenantID, userID)
		if err != nil {
			return err
		}
		if cur == identity.RoleOwner {
			n, err := ownerCount(ctx, tx, tenantID)
			if err != nil {
				return err
			}
			if n <= 1 {
				return ErrLastOwner
			}
		}
		_, err = tx.Exec(ctx, `DELETE FROM ident.memberships WHERE tenant_id = $1 AND user_id = $2`, tenantID, userID)
		return err
	})
}
