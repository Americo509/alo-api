// Package pgtest sobe um Postgres real em container para testes de
// integração, aplica as migrations e entrega dois pools:
//   - Owner: dono das tabelas (para preparar dados de teste);
//   - App:   login membro de app_rw, igual à aplicação em produção (RLS ativo).
package pgtest

import (
	"context"
	"crypto/rand"
	"database/sql"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib" // driver database/sql para o goose
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/zapgateway/zap-gateway/internal/storage/postgres"
	"github.com/zapgateway/zap-gateway/migrations"
)

const (
	image     = "pgvector/pgvector:0.8.1-pg16"
	ownerUser = "app_owner"
	appUser   = "app_test"
	dbName    = "zapgateway"
)

// randomPassword gera uma senha descartável por execução: nada fixo no código.
func randomPassword() string { return rand.Text() }

// DB é um Postgres de teste com migrations aplicadas.
type DB struct {
	Owner    *pgxpool.Pool
	App      *pgxpool.Pool
	OwnerDSN string
}

// Start sobe o container (um por chamada; use em TestMain ou sync.Once).
func Start(ctx context.Context) (*DB, func(), error) {
	ownerPass, appPass := randomPassword(), randomPassword()
	c, err := testcontainers.Run(ctx, image,
		testcontainers.WithEnv(map[string]string{
			"POSTGRES_USER":     ownerUser,
			"POSTGRES_PASSWORD": ownerPass,
			"POSTGRES_DB":       dbName,
		}),
		testcontainers.WithExposedPorts("5432/tcp"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").WithOccurrence(2).WithStartupTimeout(90*time.Second)),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("pgtest: subir postgres: %w", err)
	}
	stop := func() { _ = testcontainers.TerminateContainer(c) }

	hostPort, err := c.PortEndpoint(ctx, "5432/tcp", "")
	if err != nil {
		stop()
		return nil, nil, err
	}
	dsn := func(user, pass string) string {
		u := url.URL{Scheme: "postgres", User: url.UserPassword(user, pass), Host: hostPort, Path: dbName, RawQuery: "sslmode=disable"}
		return u.String()
	}

	ownerDSN := dsn(ownerUser, ownerPass)
	sqldb, err := sql.Open("pgx", ownerDSN)
	if err != nil {
		stop()
		return nil, nil, err
	}
	defer func() { _ = sqldb.Close() }()
	if err := migrations.Up(ctx, sqldb); err != nil {
		stop()
		return nil, nil, err
	}
	if _, err := sqldb.ExecContext(ctx, fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD '%s' IN ROLE app_rw", appUser, appPass)); err != nil {
		stop()
		return nil, nil, fmt.Errorf("pgtest: criar login da aplicação: %w", err)
	}

	owner, err := pgxpool.New(ctx, ownerDSN)
	if err != nil {
		stop()
		return nil, nil, err
	}
	app, err := pgxpool.New(ctx, dsn(appUser, appPass))
	if err != nil {
		owner.Close()
		stop()
		return nil, nil, err
	}
	return &DB{Owner: owner, App: app, OwnerDSN: ownerDSN}, func() { app.Close(); owner.Close(); stop() }, nil
}

// NewTenantWithInstance cria um tenant e uma instância e devolve os IDs.
func (d *DB) NewTenantWithInstance(t testing.TB) (tenantID, instanceID uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	tenantID, instanceID = uuid.New(), uuid.New()
	err := postgres.WithTenantTx(ctx, d.Owner, tenantID, pgx.TxOptions{}, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO core.tenants (id, name) VALUES ($1, 'tenant de teste')`, tenantID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO core.instances (id, tenant_id) VALUES ($1, $2)`, instanceID, tenantID)
		return err
	})
	if err != nil {
		t.Fatalf("pgtest: criar tenant/instância: %v", err)
	}
	return tenantID, instanceID
}
