// Package migrations embute as migrations SQL e as aplica com goose.
// Rodam com a role dona das tabelas (app_owner), nunca com a role da aplicação.
package migrations

import (
	"context"
	"database/sql"
	"embed"
	"fmt"

	"github.com/pressly/goose/v3"
)

//go:embed *.sql
var files embed.FS

// Up aplica todas as migrations pendentes.
func Up(ctx context.Context, db *sql.DB) error {
	p, err := goose.NewProvider(goose.DialectPostgres, db, files)
	if err != nil {
		return fmt.Errorf("migrations: criar provider: %w", err)
	}
	if _, err := p.Up(ctx); err != nil {
		return fmt.Errorf("migrations: aplicar: %w", err)
	}
	return nil
}
