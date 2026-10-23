package tenant

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Americo509/alo-api/internal/identity"
	"github.com/Americo509/alo-api/internal/storage/postgres"
)

// InvitePG é o InviteStore em Postgres. Mudanças que dependem do estado do
// tenant (limite, aceite) travam a linha do tenant, como o PG de membros.
type InvitePG struct{ db DB }

// NewInvitePG cria o store.
func NewInvitePG(db DB) *InvitePG { return &InvitePG{db: db} }

const inviteCols = `id, tenant_id, email, role, COALESCE(invited_by, '00000000-0000-0000-0000-000000000000'), created_at, expires_at`

func scanInvite(row pgx.Row) (Invitation, error) {
	var inv Invitation
	var role string
	if err := row.Scan(&inv.ID, &inv.TenantID, &inv.Email, &role, &inv.InvitedBy, &inv.CreatedAt, &inv.ExpiresAt); err != nil {
		return Invitation{}, err
	}
	inv.Role = identity.Role(role)
	return inv, nil
}

const pendingSQL = `accepted_at IS NULL AND revoked_at IS NULL`

// Create implementa InviteStore.
func (s *InvitePG) Create(ctx context.Context, inv Invitation, hash []byte, now time.Time) error {
	return postgres.WithTenantTx(ctx, s.db, inv.TenantID, pgx.TxOptions{}, func(tx pgx.Tx) error {
		if err := lockTenant(ctx, tx, inv.TenantID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`UPDATE ident.invitations SET revoked_at = $3
			 WHERE tenant_id = $1 AND lower(email) = lower($2) AND `+pendingSQL, inv.TenantID, inv.Email, now); err != nil {
			return err
		}
		var n int
		if err := tx.QueryRow(ctx,
			`SELECT count(*) FROM ident.invitations WHERE tenant_id = $1 AND `+pendingSQL+` AND expires_at > $2`,
			inv.TenantID, now).Scan(&n); err != nil {
			return err
		}
		if n >= MaxPendingInvites {
			return ErrTooManyInvites
		}
		_, err := tx.Exec(ctx,
			`INSERT INTO ident.invitations (id, tenant_id, email, role, token_hash, invited_by, created_at, expires_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			inv.ID, inv.TenantID, inv.Email, string(inv.Role), hash, inv.InvitedBy, inv.CreatedAt, inv.ExpiresAt)
		return err
	})
}

// Find implementa InviteStore.
func (s *InvitePG) Find(ctx context.Context, hash []byte) (Invitation, error) {
	inv, err := scanInvite(s.db.QueryRow(ctx, `SELECT `+inviteCols+` FROM ident.invitations WHERE token_hash = $1`, hash))
	if errors.Is(err, pgx.ErrNoRows) {
		return Invitation{}, ErrInvalidInvite
	}
	return inv, err
}

// Accept implementa InviteStore.
func (s *InvitePG) Accept(ctx context.Context, hash []byte, userID uuid.UUID, email string, now time.Time) (Invitation, error) {
	first, err := s.Find(ctx, hash)
	if err != nil {
		return Invitation{}, err
	}
	var out Invitation
	err = postgres.WithTenantTx(ctx, s.db, first.TenantID, pgx.TxOptions{}, func(tx pgx.Tx) error {
		if err := lockTenant(ctx, tx, first.TenantID); err != nil {
			if errors.Is(err, ErrNotFound) {
				return ErrInvalidInvite
			}
			return err
		}
		inv, err := scanInvite(tx.QueryRow(ctx,
			`SELECT `+inviteCols+` FROM ident.invitations
			 WHERE token_hash = $1 AND `+pendingSQL+` AND expires_at > $2 FOR UPDATE`, hash, now))
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && !strings.EqualFold(inv.Email, email)) {
			return ErrInvalidInvite
		}
		if err != nil {
			return err
		}
		var status string
		if err := tx.QueryRow(ctx, `SELECT status FROM core.tenants WHERE id = $1`, inv.TenantID).Scan(&status); err != nil {
			return err
		}
		if Status(status) != StatusActive {
			return ErrInvalidInvite
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO ident.memberships (user_id, tenant_id, role) VALUES ($1, $2, $3)`,
			userID, inv.TenantID, string(inv.Role)); err != nil {
			if pgCode(err) == pgUniqueViolation {
				return ErrAlreadyMember
			}
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE ident.invitations SET accepted_at = $2 WHERE id = $1`, inv.ID, now); err != nil {
			return err
		}
		out = inv
		return nil
	})
	return out, err
}

// Pending implementa InviteStore.
func (s *InvitePG) Pending(ctx context.Context, tenantID uuid.UUID, now time.Time) ([]Invitation, error) {
	rows, err := s.db.Query(ctx,
		`SELECT `+inviteCols+` FROM ident.invitations
		 WHERE tenant_id = $1 AND `+pendingSQL+` AND expires_at > $2 ORDER BY created_at, id`, tenantID, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Invitation
	for rows.Next() {
		inv, err := scanInvite(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, inv)
	}
	return out, rows.Err()
}

// Revoke implementa InviteStore.
func (s *InvitePG) Revoke(ctx context.Context, tenantID, id uuid.UUID, now time.Time) error {
	tag, err := s.db.Exec(ctx,
		`UPDATE ident.invitations SET revoked_at = $3
		 WHERE id = $1 AND tenant_id = $2 AND `+pendingSQL+` AND expires_at > $3`, id, tenantID, now)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
