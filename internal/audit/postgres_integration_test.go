//go:build integration

package audit_test

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Americo509/alo-api/internal/audit"
	"github.com/Americo509/alo-api/internal/clock"
	"github.com/Americo509/alo-api/internal/crypto/envelope"
	"github.com/Americo509/alo-api/internal/crypto/envelope/envelopetest"
	"github.com/Americo509/alo-api/internal/identity"
	"github.com/Americo509/alo-api/internal/storage/postgres/pgtest"
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

var t0 = time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)

func newPG(t *testing.T) (*audit.PG, *clock.Fake) {
	t.Helper()
	clk := clock.NewFake(t0)
	key, _, err := envelope.New(envelopetest.New()).GenerateKey(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	pg, err := audit.NewPG(db.App, key, clk)
	if err != nil {
		t.Fatal(err)
	}
	return pg, clk
}

func newUser(t *testing.T) uuid.UUID {
	t.Helper()
	u, err := identity.NewRepo(db.App).CreateUser(context.Background(), uuid.NewString()+"@example.com", "", true)
	if err != nil {
		t.Fatal(err)
	}
	return u.ID
}

func TestPGRecordAndRecentWithEncryptedDetail(t *testing.T) {
	ctx := context.Background()
	pg, clk := newPG(t)
	uid := newUser(t)
	_ = pg.Record(ctx, audit.Event{Type: audit.LoginSuccess, UserID: uid, IP: "203.0.113.77", UserAgent: "Firefox/130", Meta: map[string]string{"via": "senha"}})
	clk.Advance(time.Minute)
	_ = pg.Record(ctx, audit.Event{Type: audit.PasswordChanged, UserID: uid, IP: "203.0.113.77"})

	got, err := pg.RecentByUser(ctx, uid, 10)
	if err != nil || len(got) != 2 || got[0].Type != audit.PasswordChanged || got[1].IP != "203.0.113.77" || got[1].Meta["via"] != "senha" {
		t.Fatalf("RecentByUser = %+v, %v", got, err)
	}
	// IP e User-Agent nunca em claro no banco.
	var enc []byte
	if err := db.Owner.QueryRow(ctx, `SELECT detail_enc FROM ident.auth_events WHERE user_id = $1 ORDER BY at LIMIT 1`, uid).Scan(&enc); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(enc, []byte("203.0.113.77")) || bytes.Contains(enc, []byte("Firefox")) {
		t.Fatal("IP ou User-Agent em claro no banco")
	}
}

func TestPGEventsAreAppendOnly(t *testing.T) {
	ctx := context.Background()
	pg, _ := newPG(t)
	uid := newUser(t)
	_ = pg.Record(ctx, audit.Event{Type: audit.Logout, UserID: uid})

	// A app_rw não consegue alterar nem apagar.
	if _, err := db.App.Exec(ctx, `UPDATE ident.auth_events SET event = 'x' WHERE user_id = $1`, uid); err == nil {
		t.Fatal("UPDATE em evento de auditoria foi aceito")
	}
	if _, err := db.App.Exec(ctx, `DELETE FROM ident.auth_events WHERE user_id = $1`, uid); err == nil {
		t.Fatal("a app_rw conseguiu apagar evento de auditoria")
	}
	// Nem o dono da tabela consegue alterar (gatilho).
	if _, err := db.Owner.Exec(ctx, `UPDATE ident.auth_events SET event = 'x' WHERE user_id = $1`, uid); err == nil {
		t.Fatal("o gatilho de imutabilidade não bloqueou o UPDATE")
	}
}

// Excluir o usuário (direito da LGPD) mantém o evento, só sem o vínculo.
func TestPGUserDeletionKeepsEventWithoutLink(t *testing.T) {
	ctx := context.Background()
	pg, _ := newPG(t)
	uid := newUser(t)
	_ = pg.Record(ctx, audit.Event{Type: audit.LoginSuccess, UserID: uid})

	if _, err := db.Owner.Exec(ctx, `DELETE FROM ident.users WHERE id = $1`, uid); err != nil {
		t.Fatalf("a exclusão do usuário foi bloqueada pelo gatilho: %v", err)
	}
	var n int
	if err := db.Owner.QueryRow(ctx, `SELECT count(*) FROM ident.auth_events WHERE user_id IS NULL AND event = 'login_ok'`).Scan(&n); err != nil || n < 1 {
		t.Fatalf("evento sumiu com o usuário: %d %v", n, err)
	}
}
