package store

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Americo509/alo-api/internal/clock"
	"github.com/Americo509/alo-api/internal/crypto/envelope"
	"github.com/Americo509/alo-api/internal/storage/postgres"
)

// OpenConfig reúne o necessário para o worker abrir o store de uma instância
// que acabou de adquirir (lease + fencing token).
type OpenConfig struct {
	DB         postgres.Beginner
	TenantID   uuid.UUID
	InstanceID uuid.UUID
	Fence      int64
	Owner      string
	Envelope   *envelope.Service
	Clock      clock.Clock
	Log        *slog.Logger
	OnFenced   func()
}

// Open registra a posse no Postgres, abre (ou cria) a chave da instância e
// devolve o Store e o Container prontos.
func Open(ctx context.Context, cfg OpenConfig) (*Store, *Container, error) {
	if err := ClaimOwnership(ctx, cfg.DB, cfg.TenantID, cfg.InstanceID, cfg.Fence, cfg.Owner); err != nil {
		return nil, nil, err
	}
	key, err := LoadOrCreateKey(ctx, cfg.DB, cfg.Envelope, cfg.TenantID, cfg.InstanceID)
	if err != nil {
		return nil, nil, err
	}
	s, err := New(Config{
		DB: cfg.DB, TenantID: cfg.TenantID, InstanceID: cfg.InstanceID, Fence: cfg.Fence,
		Key: key, Clock: cfg.Clock, Log: cfg.Log, OnFenced: cfg.OnFenced,
	})
	if err != nil {
		key.Destroy()
		return nil, nil, err
	}
	return s, NewContainer(s), nil
}

// ClaimOwnership grava o fencing token do novo dono. Só avança: se já existe
// um token maior ou igual de outro dono, devolve ErrFenced. O UPDATE espera
// as transações de escrita em andamento do dono anterior (que seguram FOR
// SHARE), e depois delas qualquer escrita do dono anterior é recusada.
func ClaimOwnership(ctx context.Context, db postgres.Beginner, tenantID, instanceID uuid.UUID, fence int64, owner string) error {
	if fence <= 0 || owner == "" {
		return errors.New("store: fence e owner são obrigatórios")
	}
	return postgres.WithTenantTx(ctx, db, tenantID, pgx.TxOptions{}, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			INSERT INTO wa.instance_owner (instance_id, tenant_id, fence, owner) VALUES ($1, $2, $3, $4)
			ON CONFLICT (instance_id) DO UPDATE SET fence = excluded.fence, owner = excluded.owner, updated_at = now()
				WHERE wa.instance_owner.fence < excluded.fence`,
			instanceID, tenantID, fence, owner)
		if err != nil {
			return fmt.Errorf("store: registrar posse: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return ErrFenced
		}
		return nil
	})
}

// LoadOrCreateKey abre a DEK da instância; na primeira vez, gera e grava.
func LoadOrCreateKey(ctx context.Context, db postgres.Beginner, env *envelope.Service, tenantID, instanceID uuid.UUID) (*envelope.DataKey, error) {
	var w envelope.WrappedKey
	err := postgres.WithTenantTx(ctx, db, tenantID, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT master_key_ref, wrapped_dek FROM wa.instance_keys WHERE instance_id = $1`,
			instanceID).Scan(&w.MasterKeyRef, &w.Ciphertext)
	})
	if err == nil {
		return env.OpenKey(ctx, w)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("store: ler chave da instância: %w", err)
	}

	dk, w, err := env.GenerateKey(ctx)
	if err != nil {
		return nil, err
	}
	var inserted bool
	err = postgres.WithTenantTx(ctx, db, tenantID, pgx.TxOptions{}, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			INSERT INTO wa.instance_keys (instance_id, tenant_id, master_key_ref, wrapped_dek) VALUES ($1, $2, $3, $4)
			ON CONFLICT (instance_id) DO NOTHING`,
			instanceID, tenantID, w.MasterKeyRef, w.Ciphertext)
		inserted = tag.RowsAffected() == 1
		return err
	})
	if err != nil {
		dk.Destroy()
		return nil, fmt.Errorf("store: gravar chave da instância: %w", err)
	}
	if inserted {
		return dk, nil
	}
	// Outro processo criou ao mesmo tempo: usa a dele.
	dk.Destroy()
	return LoadOrCreateKey(ctx, db, env, tenantID, instanceID)
}
