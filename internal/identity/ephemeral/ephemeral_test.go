package ephemeral

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Americo509/alo-api/internal/clock"
)

var (
	ctx = context.Background()
	t0  = time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
)

func TestTakeConsumes(t *testing.T) {
	s := NewMemory(clock.NewFake(t0))
	_ = s.Put(ctx, "k", []byte("v"), time.Minute)
	got, err := s.Take(ctx, "k")
	if err != nil || string(got) != "v" {
		t.Fatalf("Take = %q, %v", got, err)
	}
	if _, err := s.Take(ctx, "k"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("segundo Take deveria falhar: %v", err)
	}
}

func TestExpiry(t *testing.T) {
	clk := clock.NewFake(t0)
	s := NewMemory(clk)
	_ = s.Put(ctx, "k", []byte("v"), time.Minute)
	clk.Advance(61 * time.Second)
	if _, err := s.Take(ctx, "k"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("valor expirado devolvido: %v", err)
	}
}

// Sob concorrência, exatamente uma chamada consome o valor.
func TestTakeIsSingleUseUnderConcurrency(t *testing.T) {
	s := NewMemory(clock.NewFake(t0))
	_ = s.Put(ctx, "k", []byte("v"), time.Minute)
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.Take(ctx, "k"); err == nil {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d chamadas consumiram o mesmo valor, quer exatamente 1", wins.Load())
	}
}

func TestTokenAndKey(t *testing.T) {
	tok, key, err := NewToken(nil)
	if err != nil {
		t.Fatal(err)
	}
	back, err := KeyOf(tok)
	if err != nil || back != key {
		t.Fatalf("KeyOf(token) = %q, %v; quer %q", back, err, key)
	}
	if key == tok {
		t.Fatal("a chave de armazenamento não pode ser o próprio token")
	}
	for _, bad := range []string{"", "!!!", tok + "x", tok[:10]} {
		if _, err := KeyOf(bad); !errors.Is(err, ErrNotFound) {
			t.Errorf("token inválido %q aceito: %v", bad, err)
		}
	}
	tok2, _, _ := NewToken(nil)
	if tok == tok2 {
		t.Fatal("tokens repetidos")
	}
}
