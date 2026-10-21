//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/zapgateway/zap-gateway/internal/storage/postgres"
	"github.com/zapgateway/zap-gateway/internal/storage/postgres/pgtest"
)

var db *pgtest.DB

func TestMain(m *testing.M) {
	var stop func()
	var err error
	db, stop, err = pgtest.Start(context.Background())
	if err != nil {
		panic(err)
	}
	code := m.Run()
	stop()
	os.Exit(code)
}

// Toda tabela com tenant_id (ou core.tenants) tem RLS habilitado E forçado e
// ao menos uma política. Tabela nova sem isso quebra o CI (ADR-0006, item 6).
func TestEveryTenantTableHasForcedRLS(t *testing.T) {
	ctx := context.Background()
	rows, err := db.Owner.Query(ctx, `
		SELECT n.nspname || '.' || c.relname, c.relrowsecurity, c.relforcerowsecurity,
		       EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = c.oid)
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE c.relkind = 'r' AND n.nspname IN ('core', 'wa')
		  AND (EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped)
		       OR (n.nspname = 'core' AND c.relname = 'tenants'))`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var name string
		var enabled, forced, hasPolicy bool
		if err := rows.Scan(&name, &enabled, &forced, &hasPolicy); err != nil {
			t.Fatal(err)
		}
		n++
		if !enabled || !forced || !hasPolicy {
			t.Errorf("%s: rls=%t force=%t politica=%t", name, enabled, forced, hasPolicy)
		}
	}
	if n < 18 {
		t.Fatalf("só %d tabelas verificadas; a consulta do catálogo está errada?", n)
	}
}

// Papel da aplicação não pode ignorar RLS nem ser dono de tabela.
func TestAppRoleCannotBypassRLS(t *testing.T) {
	var bypass, super bool
	err := db.App.QueryRow(context.Background(),
		`SELECT rolbypassrls, rolsuper FROM pg_roles WHERE rolname = current_user`).Scan(&bypass, &super)
	if err != nil || bypass || super {
		t.Fatalf("app: bypassrls=%t superuser=%t err=%v", bypass, super, err)
	}
}

func TestTenantIsolation(t *testing.T) {
	ctx := context.Background()
	tenantA, instA := db.NewTenantWithInstance(t)
	tenantB, _ := db.NewTenantWithInstance(t)

	// A grava um dado no store.
	err := postgres.WithTenantTx(ctx, db.App, tenantA, pgx.TxOptions{}, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO wa.nct_salt (instance_id, tenant_id, salt_enc) VALUES ($1, $2, '\x01')`, instA, tenantA)
		return err
	})
	if err != nil {
		t.Fatalf("A grava: %v", err)
	}

	// B não lê, não altera e não apaga o dado de A.
	err = postgres.WithTenantTx(ctx, db.App, tenantB, pgx.TxOptions{}, func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM wa.nct_salt WHERE instance_id = $1`, instA).Scan(&n); err != nil {
			return err
		}
		if n != 0 {
			t.Errorf("B leu %d linhas de A", n)
		}
		if tag, err := tx.Exec(ctx, `UPDATE wa.nct_salt SET salt_enc = '\x02' WHERE instance_id = $1`, instA); err != nil || tag.RowsAffected() != 0 {
			t.Errorf("B alterou dado de A: linhas=%d err=%v", tag.RowsAffected(), err)
		}
		if tag, err := tx.Exec(ctx, `DELETE FROM wa.nct_salt WHERE instance_id = $1`, instA); err != nil || tag.RowsAffected() != 0 {
			t.Errorf("B apagou dado de A: linhas=%d err=%v", tag.RowsAffected(), err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// B não consegue gravar com tenant_id de A (WITH CHECK).
	err = postgres.WithTenantTx(ctx, db.App, tenantB, pgx.TxOptions{}, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO wa.nct_salt (instance_id, tenant_id, salt_enc) VALUES ($1, $2, '\x03')`, uuid.New(), tenantA)
		return err
	})
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
		t.Fatalf("B gravou com tenant de A: %v", err)
	}

	// Mesmo com o tenant certo, não dá para ligar dado à instância de outro tenant (FK composta).
	err = postgres.WithTenantTx(ctx, db.App, tenantB, pgx.TxOptions{}, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO wa.devices (instance_id, tenant_id, device_enc) VALUES ($1, $2, '\x04')`, instA, tenantB)
		return err
	})
	if !errors.As(err, &pgErr) || pgErr.Code != "23503" {
		t.Fatalf("dado ligado a instância de outro tenant: %v", err)
	}
}

// Sem tenant definido, a consulta FALHA em vez de devolver vazio.
func TestQueryWithoutTenantFails(t *testing.T) {
	ctx := context.Background()
	var n int
	err := db.App.QueryRow(ctx, `SELECT count(*) FROM wa.sessions`).Scan(&n)
	if err == nil {
		t.Fatalf("consulta sem tenant devolveu %d em vez de erro", n)
	}
}

// O tenant definido numa transação não vaza para a próxima transação da mesma conexão.
func TestTenantDoesNotLeakThroughPool(t *testing.T) {
	ctx := context.Background()
	tenantA, _ := db.NewTenantWithInstance(t)
	conn, err := db.App.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	if err := postgres.WithTenantTx(ctx, conn, tenantA, pgx.TxOptions{}, func(pgx.Tx) error { return nil }); err != nil {
		t.Fatal(err)
	}
	var v string
	if err := conn.QueryRow(ctx, `SELECT coalesce(current_setting('app.tenant_id', true), '')`).Scan(&v); err != nil {
		t.Fatal(err)
	}
	if v != "" {
		t.Fatalf("tenant vazou para fora da transação: %q", v)
	}
}
