//go:build integration

package mailer_test

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Americo509/alo-api/internal/mailer"
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

var base = time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)

func item() mailer.Item {
	return mailer.Item{ID: uuid.New(), Kind: mailer.KindVerification, Payload: []byte("cifrado"), ExpiresAt: base.Add(time.Hour)}
}

func TestPGOutboxLifecycle(t *testing.T) {
	ctx := context.Background()
	ob := mailer.NewPGOutbox(db.App)
	it := item()
	if err := ob.Enqueue(ctx, it, base); err != nil {
		t.Fatal(err)
	}

	got, err := ob.Claim(ctx, base, 10, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	var mine *mailer.Item
	for i := range got {
		if got[i].ID == it.ID {
			mine = &got[i]
		}
	}
	if mine == nil || mine.Attempts != 1 || string(mine.Payload) != "cifrado" || mine.Kind != mailer.KindVerification {
		t.Fatalf("Claim = %+v", got)
	}
	// Reservado: um segundo Claim no mesmo instante não o devolve.
	again, _ := ob.Claim(ctx, base, 10, time.Minute)
	for _, g := range again {
		if g.ID == it.ID {
			t.Fatal("item reservado foi entregue a dois despachantes")
		}
	}
	// Depois do lease ele volta, com tentativas incrementadas.
	later, _ := ob.Claim(ctx, base.Add(2*time.Minute), 10, time.Minute)
	found := false
	for _, g := range later {
		if g.ID == it.ID && g.Attempts == 2 {
			found = true
		}
	}
	if !found {
		t.Fatalf("item não voltou após o lease: %+v", later)
	}

	if err := ob.Retry(ctx, it.ID, base.Add(time.Hour), "smtp"); err != nil {
		t.Fatal(err)
	}
	if got, _ := ob.Claim(ctx, base.Add(10*time.Minute), 10, time.Minute); contains(got, it.ID) {
		t.Fatal("item reagendado voltou antes da hora")
	}
	if err := ob.Done(ctx, it.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := ob.Claim(ctx, base.Add(3*time.Hour), 10, time.Minute); contains(got, it.ID) {
		t.Fatal("item concluído ainda na fila")
	}
}

func TestPGOutboxDeadErasesPayloadAndPurges(t *testing.T) {
	ctx := context.Background()
	ob := mailer.NewPGOutbox(db.App)
	it := item()
	_ = ob.Enqueue(ctx, it, base)
	if err := ob.Dead(ctx, it.ID, base, "smtp"); err != nil {
		t.Fatal(err)
	}
	var payloadIsNull bool
	if err := db.App.QueryRow(ctx, `SELECT payload_enc IS NULL FROM ident.email_outbox WHERE id = $1`, it.ID).Scan(&payloadIsNull); err != nil || !payloadIsNull {
		t.Fatalf("o conteúdo do e-mail morto deveria ser apagado: null=%t err=%v", payloadIsNull, err)
	}
	n, err := ob.PurgeDead(ctx, base.Add(time.Hour))
	if err != nil || n < 1 {
		t.Fatalf("PurgeDead = %d, %v", n, err)
	}
}

// Vários despachantes ao mesmo tempo (SKIP LOCKED) nunca recebem o mesmo item.
func TestPGOutboxSkipLockedUnderConcurrency(t *testing.T) {
	ctx := context.Background()
	ob := mailer.NewPGOutbox(db.App)
	ids := map[uuid.UUID]bool{}
	for range 30 {
		it := item()
		ids[it.ID] = true
		if err := ob.Enqueue(ctx, it, base); err != nil {
			t.Fatal(err)
		}
	}
	var mu sync.Mutex
	seen := map[uuid.UUID]int{}
	var wg sync.WaitGroup
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				got, err := ob.Claim(ctx, base, 4, time.Hour)
				if err != nil || len(got) == 0 {
					return
				}
				mu.Lock()
				for _, g := range got {
					seen[g.ID]++
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	for id := range ids {
		if seen[id] != 1 {
			t.Errorf("item %v foi reservado %d vezes, quer 1", id, seen[id])
		}
	}
}

func contains(items []mailer.Item, id uuid.UUID) bool {
	for _, i := range items {
		if i.ID == id {
			return true
		}
	}
	return false
}
