// Package store implementa as interfaces de persistência do whatsmeow
// (store.AllSessionSpecificStores, store.LIDStore e store.DeviceContainer)
// sobre o schema wa do Postgres, conforme o ADR-0010:
//
//   - todo segredo e todo dado pessoal vai cifrado com a chave da instância,
//     com AAD amarrando o blob à instância, à tabela e à chave lógica;
//   - telefones, JIDs e IDs de conversa só aparecem como blind index;
//   - toda transação define o tenant (RLS, ADR-0006);
//   - toda escrita confere o fencing token (ADR-0005): dono antigo não grava.
//
// Um Store atende exatamente uma instância e só deve existir no worker que
// detém o lease dela.
package store

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/zapgateway/zap-gateway/internal/clock"
	"github.com/zapgateway/zap-gateway/internal/crypto/envelope"
	"github.com/zapgateway/zap-gateway/internal/storage/postgres"
)

var (
	// ErrFenced: outro worker assumiu a instância (fencing token mais novo).
	// O worker deve desconectar a sessão imediatamente.
	ErrFenced = errors.New("store: escrita recusada, instância pertence a outro worker")
	// ErrDeviceIDMustBeSet: mesmo contrato do sqlstore.
	ErrDeviceIDMustBeSet = errors.New("store: JID da device precisa ser conhecido antes de gravar")
	// ErrInvalidLength: dado decifrado com tamanho inesperado.
	ErrInvalidLength = errors.New("store: dado com tamanho inválido")
	// ErrNotFound: usado onde o contrato do whatsmeow espera erro em vez de nil.
	ErrNotFound = errors.New("store: registro não encontrado")
)

// Domínios de blind index. Mudar um valor invalida as buscas existentes.
const (
	idxSignalUser = "signal-user" // parte "usuário" de um endereço Signal
	idxJID        = "jid"         // JID completo (contato, conversa, remetente)
	idxLIDUser    = "lid-user"
	idxPNUser     = "pn-user"
)

// Config reúne as dependências de um Store.
type Config struct {
	DB         postgres.Beginner
	TenantID   uuid.UUID
	InstanceID uuid.UUID
	// Fence é o fencing token do lease atual (ADR-0005).
	Fence int64
	// Key é a chave de dados da instância, já aberta.
	Key   *envelope.DataKey
	Clock clock.Clock
	Log   *slog.Logger
	// OnFenced é chamado uma vez quando uma escrita é recusada por fencing.
	OnFenced func()
}

// Store é a implementação para uma instância.
type Store struct {
	db         postgres.Beginner
	tenantID   uuid.UUID
	instanceID uuid.UUID
	fence      int64
	key        *envelope.DataKey
	clock      clock.Clock
	log        *slog.Logger
	onFenced   func()
	fencedOnce sync.Once

	preKeyMu sync.Mutex

	contactMu    sync.Mutex
	contactCache map[string]*contactRecord

	migratedMu sync.Mutex
	migratedPN map[string]struct{}

	lids *LIDMap
}

// New cria o Store. Não acessa o banco.
func New(cfg Config) (*Store, error) {
	switch {
	case cfg.DB == nil || cfg.Key == nil || cfg.Clock == nil:
		return nil, errors.New("store: DB, Key e Clock são obrigatórios")
	case cfg.TenantID == uuid.Nil || cfg.InstanceID == uuid.Nil:
		return nil, errors.New("store: tenant e instância são obrigatórios")
	case cfg.Fence <= 0:
		return nil, errors.New("store: fencing token inválido")
	}
	log := cfg.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	s := &Store{
		db:           cfg.DB,
		tenantID:     cfg.TenantID,
		instanceID:   cfg.InstanceID,
		fence:        cfg.Fence,
		key:          cfg.Key,
		clock:        cfg.Clock,
		log:          log.With(slog.String("instance_id", cfg.InstanceID.String())),
		onFenced:     cfg.OnFenced,
		contactCache: map[string]*contactRecord{},
		migratedPN:   map[string]struct{}{},
	}
	s.lids = newLIDMap(s)
	return s, nil
}

// LIDs devolve o mapa LID↔telefone desta instância.
func (s *Store) LIDs() *LIDMap { return s.lids }

// ---------------------------------------------------------------------------
// Transações

type txKey struct{ s *Store }

type txState struct {
	mu sync.Mutex
	tx pgx.Tx
}

func (s *Store) txFrom(ctx context.Context) *txState {
	st, _ := ctx.Value(txKey{s}).(*txState)
	return st
}

// read executa fn numa transação somente-leitura (ou na transação do ctx).
func (s *Store) read(ctx context.Context, fn func(context.Context, pgx.Tx) error) error {
	if st := s.txFrom(ctx); st != nil {
		st.mu.Lock()
		defer st.mu.Unlock()
		return fn(ctx, st.tx)
	}
	return postgres.WithTenantTx(ctx, s.db, s.tenantID, pgx.TxOptions{AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		return fn(ctx, tx)
	})
}

// write executa fn numa transação de escrita com checagem de fencing (ou na
// transação do ctx, que já foi checada ao abrir).
func (s *Store) write(ctx context.Context, fn func(context.Context, pgx.Tx) error) error {
	if st := s.txFrom(ctx); st != nil {
		st.mu.Lock()
		defer st.mu.Unlock()
		return fn(ctx, st.tx)
	}
	return postgres.WithTenantTx(ctx, s.db, s.tenantID, pgx.TxOptions{}, func(tx pgx.Tx) error {
		if err := s.checkFence(ctx, tx); err != nil {
			return err
		}
		return fn(ctx, tx)
	})
}

// DoTxn executa fn numa transação de escrita compartilhada por todas as
// chamadas do store que receberem o ctx repassado. Chamadas aninhadas
// reaproveitam a transação externa.
func (s *Store) DoTxn(ctx context.Context, fn func(context.Context) error) error {
	if s.txFrom(ctx) != nil {
		return fn(ctx)
	}
	return postgres.WithTenantTx(ctx, s.db, s.tenantID, pgx.TxOptions{}, func(tx pgx.Tx) error {
		if err := s.checkFence(ctx, tx); err != nil {
			return err
		}
		return fn(context.WithValue(ctx, txKey{s}, &txState{tx: tx}))
	})
}

// checkFence trava a linha de dono em modo compartilhado até o fim da
// transação: a troca de dono (UPDATE) espera as escritas em andamento, e
// escritas de um dono antigo são recusadas.
func (s *Store) checkFence(ctx context.Context, tx pgx.Tx) error {
	var current int64
	err := tx.QueryRow(ctx,
		`SELECT fence FROM wa.instance_owner WHERE instance_id = $1 FOR SHARE`, s.instanceID).Scan(&current)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && current != s.fence) {
		s.fencedOnce.Do(func() {
			s.log.Error("escrita recusada por fencing", slog.Int64("fence", s.fence), slog.Int64("fence_atual", current))
			if s.onFenced != nil {
				s.onFenced()
			}
		})
		return ErrFenced
	}
	if err != nil {
		return fmt.Errorf("store: checar fencing: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Criptografia

// aad monta o dado associado: versão, instância, tabela e partes da chave
// lógica, cada uma prefixada pelo tamanho (sem ambiguidade de concatenação).
func (s *Store) aad(table string, parts ...[]byte) []byte {
	b := make([]byte, 0, 64)
	b = appendLV(b, []byte("zgw/wa/v1"))
	b = appendLV(b, s.instanceID[:])
	b = appendLV(b, []byte(table))
	for _, p := range parts {
		b = appendLV(b, p)
	}
	return b
}

func appendLV(b, v []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, uint32(len(v))) //nolint:gosec // partes curtas, controladas pelo código
	return append(b, v...)
}

func (s *Store) seal(pt []byte, table string, parts ...[]byte) ([]byte, error) {
	out, err := s.key.Seal(pt, s.aad(table, parts...))
	if err != nil {
		return nil, fmt.Errorf("store: cifrar %s: %w", table, err)
	}
	return out, nil
}

func (s *Store) open(ct []byte, table string, parts ...[]byte) ([]byte, error) {
	out, err := s.key.Open(ct, s.aad(table, parts...))
	if err != nil {
		return nil, fmt.Errorf("store: decifrar %s: %w", table, err)
	}
	return out, nil
}

func (s *Store) idx(domain, value string) ([]byte, error) {
	b, err := s.key.BlindIndex(domain, []byte(value))
	if err != nil {
		return nil, fmt.Errorf("store: blind index: %w", err)
	}
	return b, nil
}

// ---------------------------------------------------------------------------
// Endereços Signal: "usuario:aparelho"

type signalAddr struct {
	user   string
	device int32
}

func parseAddress(addr string) (signalAddr, error) {
	i := strings.LastIndexByte(addr, ':')
	if i <= 0 {
		return signalAddr{}, fmt.Errorf("store: endereço Signal inválido")
	}
	dev, err := strconv.ParseUint(addr[i+1:], 10, 31)
	if err != nil {
		return signalAddr{}, fmt.Errorf("store: aparelho inválido no endereço Signal")
	}
	return signalAddr{user: addr[:i], device: int32(dev)}, nil //nolint:gosec // limitado a 31 bits acima
}

func deviceBytes(d int32) []byte { return binary.BigEndian.AppendUint32(nil, uint32(d)) } //nolint:gosec // d >= 0
