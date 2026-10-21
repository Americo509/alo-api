// Package postgres concentra o acesso ao Postgres com isolamento por tenant
// (ADR-0006). Repositórios recebem uma pgx.Tx já com o tenant definido; nunca
// o pool.
package postgres

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Beginner é o que WithTenantTx precisa do pool (facilita teste).
type Beginner interface {
	BeginTx(ctx context.Context, opts pgx.TxOptions) (pgx.Tx, error)
}

// WithTenantTx abre uma transação, define app.tenant_id só para ela (SET
// LOCAL, via set_config(..., true)) e executa fn. Ao terminar a transação o
// valor some, então nada vaza pela conexão devolvida ao pool.
func WithTenantTx(ctx context.Context, db Beginner, tenantID uuid.UUID, opts pgx.TxOptions, fn func(pgx.Tx) error) error {
	if tenantID == uuid.Nil {
		return fmt.Errorf("postgres: tenant vazio")
	}
	return pgx.BeginTxFunc(ctx, db, opts, func(tx pgx.Tx) error {
		if err := SetTenant(ctx, tx, tenantID); err != nil {
			return err
		}
		return fn(tx)
	})
}

// SetTenant define o tenant numa transação já aberta.
func SetTenant(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID) error {
	if _, err := tx.Exec(ctx, "SELECT set_config('app.tenant_id', $1, true)", tenantID.String()); err != nil {
		return fmt.Errorf("postgres: definir tenant: %w", err)
	}
	return nil
}
