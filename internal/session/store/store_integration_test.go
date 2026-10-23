//go:build integration

package store

import (
	"bytes"
	"context"
	"errors"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	wastore "go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"

	"github.com/Americo509/alo-api/internal/clock"
	"github.com/Americo509/alo-api/internal/crypto/envelope"
	"github.com/Americo509/alo-api/internal/crypto/envelope/envelopetest"
	"github.com/Americo509/alo-api/internal/storage/postgres"
	"github.com/Americo509/alo-api/internal/storage/postgres/pgtest"
)

var (
	db  *pgtest.DB
	env = envelope.New(envelopetest.New())
	t0  = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
)

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

type fixture struct {
	tenant, instance uuid.UUID
	s                *Store
	c                *Container
	clk              *clock.Fake
	fenced           *atomic.Int32
}

func open(t *testing.T, tenant, instance uuid.UUID, fence int64, owner string) fixture {
	t.Helper()
	clk := clock.NewFake(t0)
	var fenced atomic.Int32
	s, c, err := Open(context.Background(), OpenConfig{
		DB: db.App, TenantID: tenant, InstanceID: instance, Fence: fence, Owner: owner,
		Envelope: env, Clock: clk, OnFenced: func() { fenced.Add(1) },
	})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return fixture{tenant: tenant, instance: instance, s: s, c: c, clk: clk, fenced: &fenced}
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	tenant, instance := db.NewTenantWithInstance(t)
	return open(t, tenant, instance, 1, "worker-teste")
}

// Valores marcados para procurar depois no banco.
const (
	phone      = "5511987654321"
	contactNm  = "Maria Paciente Teste"
	secretMark = "SEGREDO-DE-SESSAO-0123456789"
)

// Grava um pouco de tudo e confere que nenhum telefone, nome ou segredo
// aparece em claro em nenhuma coluna de nenhuma tabela do schema wa.
func TestNothingSensitiveInPlaintext(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	addr := phone + ":0"
	pnJID := types.NewJID(phone, types.DefaultUserServer)

	must(t, f.s.PutSession(ctx, addr, []byte(secretMark)))
	var ik [32]byte
	copy(ik[:], secretMark)
	must(t, f.s.PutIdentity(ctx, addr, ik))
	must(t, f.s.PutSenderKey(ctx, "120363000000000000@g.us", addr, []byte(secretMark)))
	must(t, f.s.PutContactName(ctx, pnJID, "Maria", contactNm))
	_, _, err := f.s.PutPushName(ctx, pnJID, contactNm)
	must(t, err)
	must(t, f.s.PutMessageSecret(ctx, pnJID, pnJID, "MSGID1", []byte(secretMark)))
	must(t, f.s.PutPrivacyTokens(ctx, wastore.PrivacyToken{User: pnJID, Token: []byte(secretMark), Timestamp: t0}))
	must(t, f.s.LIDs().PutLIDMapping(ctx, types.NewJID("99887766554433", types.HiddenUserServer), pnJID))
	must(t, f.s.PutBufferedEvent(ctx, [32]byte{1}, []byte(secretMark), t0))
	must(t, f.s.AddOutgoingEvent(ctx, pnJID, "MSGID2", "proto", []byte(secretMark)))
	must(t, f.s.PutNCTSalt(ctx, []byte(secretMark)))
	dev, err := f.c.NewDevice()
	must(t, err)
	dev.ID = &pnJID
	dev.PushName = contactNm
	must(t, dev.Save(ctx))

	for _, needle := range []string{phone, contactNm, secretMark, "99887766554433"} {
		if hits := findInSchema(t, f.tenant, []byte(needle)); len(hits) > 0 {
			t.Errorf("%q aparece em claro em: %v", needle, hits)
		}
	}
	// Chaves privadas da device também não.
	if hits := findInSchema(t, f.tenant, dev.NoiseKey.Priv[:]); len(hits) > 0 {
		t.Errorf("chave privada noise em claro em: %v", hits)
	}
}

// findInSchema varre todas as colunas texto/bytea das tabelas wa do tenant.
func findInSchema(t *testing.T, tenant uuid.UUID, needle []byte) []string {
	t.Helper()
	ctx := context.Background()
	var hits []string
	err := postgres.WithTenantTx(ctx, db.Owner, tenant, pgx.TxOptions{}, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT table_name, column_name, data_type FROM information_schema.columns
			WHERE table_schema = 'wa' AND data_type IN ('bytea', 'text')`)
		if err != nil {
			return err
		}
		type col struct{ table, column, typ string }
		var cols []col
		for rows.Next() {
			var c col
			if err := rows.Scan(&c.table, &c.column, &c.typ); err != nil {
				return err
			}
			cols = append(cols, c)
		}
		rows.Close()
		for _, c := range cols {
			expr := c.column
			if c.typ == "text" {
				expr = "convert_to(" + c.column + ", 'UTF8')"
			}
			r, err := tx.Query(ctx, `SELECT `+expr+` FROM wa.`+c.table+` WHERE `+c.column+` IS NOT NULL`)
			if err != nil {
				return err
			}
			for r.Next() {
				var v []byte
				if err := r.Scan(&v); err != nil {
					r.Close()
					return err
				}
				if bytes.Contains(v, needle) {
					hits = append(hits, c.table+"."+c.column)
				}
			}
			r.Close()
		}
		return nil
	})
	if err != nil {
		t.Fatalf("varrer schema: %v", err)
	}
	return hits
}

// Depois que outro worker assume (fence maior), o dono antigo não grava mais
// nada e é avisado; o novo dono lê o que o antigo gravou.
func TestFencingBlocksOldOwner(t *testing.T) {
	ctx := context.Background()
	old := newFixture(t)
	must(t, old.s.PutSession(ctx, "5511900000001:0", []byte("antes")))

	nw := open(t, old.tenant, old.instance, 2, "worker-novo")

	err := old.s.PutSession(ctx, "5511900000001:0", []byte("depois-do-takeover"))
	if !errors.Is(err, ErrFenced) {
		t.Fatalf("dono antigo gravou após takeover: %v", err)
	}
	if old.fenced.Load() != 1 {
		t.Fatalf("OnFenced chamado %d vezes, quer 1", old.fenced.Load())
	}
	got, err := nw.s.GetSession(ctx, "5511900000001:0")
	if err != nil || string(got) != "antes" {
		t.Fatalf("novo dono leu %q, %v", got, err)
	}
	// Transação longa do dono antigo também é barrada.
	err = old.s.DoDecryptionTxn(ctx, func(ctx context.Context) error { return nil })
	if !errors.Is(err, ErrFenced) {
		t.Fatalf("DoDecryptionTxn do dono antigo: %v", err)
	}
	// Reivindicar com fence igual ou menor falha.
	if err := ClaimOwnership(ctx, db.App, old.tenant, old.instance, 2, "outro"); !errors.Is(err, ErrFenced) {
		t.Fatalf("claim com fence repetido: %v", err)
	}
}

// Um blob copiado de uma linha para outra (mesma instância) não abre: o AAD
// amarra o valor à chave lógica.
func TestTransplantedBlobIsRejected(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	must(t, f.s.PutSession(ctx, "5511900000002:0", []byte("sessao A")))
	must(t, f.s.PutSession(ctx, "5511900000003:0", []byte("sessao B")))

	a, _ := f.s.idx(idxSignalUser, "5511900000002")
	b, _ := f.s.idx(idxSignalUser, "5511900000003")
	err := postgres.WithTenantTx(ctx, db.Owner, f.tenant, pgx.TxOptions{}, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			UPDATE wa.sessions SET session_enc = (SELECT session_enc FROM wa.sessions WHERE instance_id = $1 AND user_idx = $2)
			WHERE instance_id = $1 AND user_idx = $3`, f.instance, a, b)
		return err
	})
	must(t, err)
	if got, err := f.s.GetSession(ctx, "5511900000003:0"); err == nil {
		t.Fatalf("blob transplantado foi aceito: %q", got)
	}
}

// Outra instância (outra DEK) não abre os dados desta, mesmo no mesmo tenant.
func TestOtherInstanceKeyCannotRead(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	must(t, f.s.PutNCTSalt(ctx, []byte("sal")))

	otherKey, _, err := env.GenerateKey(ctx)
	must(t, err)
	other, err := New(Config{DB: db.App, TenantID: f.tenant, InstanceID: f.instance, Fence: 1, Key: otherKey, Clock: f.clk})
	must(t, err)
	if _, err := other.GetNCTSalt(ctx); err == nil {
		t.Fatal("chave de outra instância abriu o dado")
	}
}

func TestDeleteDeviceWipesSessionState(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	jid := types.NewJID("5511900000004", types.DefaultUserServer)
	dev, _ := f.c.NewDevice()
	dev.ID = &jid
	must(t, dev.Save(ctx))
	must(t, f.s.PutSession(ctx, "5511900000004:0", []byte("x")))
	must(t, f.s.PutContactName(ctx, jid, "A", "B"))

	must(t, dev.Delete(ctx))

	var n int
	err := postgres.WithTenantTx(ctx, db.Owner, f.tenant, pgx.TxOptions{}, func(tx pgx.Tx) error {
		for _, tbl := range sessionTables {
			var c int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM wa.`+tbl+` WHERE instance_id = $1`, f.instance).Scan(&c); err != nil {
				return err
			}
			n += c
		}
		return nil
	})
	must(t, err)
	if n != 0 {
		t.Fatalf("%d linhas sobraram após DeleteDevice", n)
	}
	reloaded, err := f.c.Device(ctx)
	must(t, err)
	if reloaded.ID != nil {
		t.Fatal("device ainda carrega após DeleteDevice")
	}
}

func TestDeviceRoundTrip(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	jid := types.NewADJID("5511900000005", 0, 3)
	dev, _ := f.c.NewDevice()
	dev.ID = &jid
	dev.LID = types.NewJID("12345678901234", types.HiddenUserServer)
	dev.PushName, dev.Platform, dev.BusinessName = "Clinica", "android", "Clínica Teste"
	dev.FacebookUUID = uuid.New()
	must(t, dev.Save(ctx))
	if !dev.Initialized {
		t.Fatal("Save não inicializou os stores da device")
	}

	// Reabrindo o store do zero (como após reiniciar o worker).
	g := open(t, f.tenant, f.instance, 2, "worker-reinicio")
	got, err := g.c.Device(ctx)
	must(t, err)
	switch {
	case got.ID == nil || *got.ID != jid:
		t.Fatalf("ID = %v", got.ID)
	case got.LID != dev.LID || got.PushName != dev.PushName || got.Platform != dev.Platform || got.BusinessName != dev.BusinessName:
		t.Fatalf("campos divergem: %+v", got)
	case got.FacebookUUID != dev.FacebookUUID || got.RegistrationID != dev.RegistrationID:
		t.Fatal("uuid/registration divergem")
	case *got.NoiseKey.Priv != *dev.NoiseKey.Priv || *got.IdentityKey.Priv != *dev.IdentityKey.Priv || *got.SignedPreKey.Priv != *dev.SignedPreKey.Priv:
		t.Fatal("chaves divergem")
	case got.SignedPreKey.KeyID != dev.SignedPreKey.KeyID || *got.SignedPreKey.Signature != *dev.SignedPreKey.Signature:
		t.Fatal("signed pre-key diverge")
	case !got.Initialized || got.Sessions == nil || got.LIDs == nil:
		t.Fatal("device carregada sem stores")
	}
}

func TestStoreRequiresTenantScopedDB(t *testing.T) {
	// Sanidade: sem tenant correto, a instância de outro tenant não é visível.
	ctx := context.Background()
	f := newFixture(t)
	must(t, f.s.PutNCTSalt(ctx, []byte("sal")))
	otherTenant, _ := db.NewTenantWithInstance(t)
	key, err := LoadOrCreateKey(ctx, db.App, env, f.tenant, f.instance)
	must(t, err)
	intruder, err := New(Config{DB: db.App, TenantID: otherTenant, InstanceID: f.instance, Fence: 1, Key: key, Clock: f.clk})
	must(t, err)
	salt, err := intruder.GetNCTSalt(ctx)
	if err != nil || salt != nil {
		t.Fatalf("store com tenant alheio leu dado: %q, %v", salt, err)
	}
	if err := intruder.PutNCTSalt(ctx, []byte("x")); !errors.Is(err, ErrFenced) {
		t.Fatalf("store com tenant alheio gravou: %v", err)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
