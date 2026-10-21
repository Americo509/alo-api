package clock

import (
	"context"
	"testing"
	"time"
)

var t0 = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

func received(c <-chan time.Time) (time.Time, bool) {
	select {
	case v := <-c:
		return v, true
	default:
		return time.Time{}, false
	}
}

func TestFakeNowOnlyMovesOnAdvance(t *testing.T) {
	f := NewFake(t0)
	if !f.Now().Equal(t0) {
		t.Fatalf("Now() = %v, quer %v", f.Now(), t0)
	}
	f.Advance(90 * time.Second)
	if want := t0.Add(90 * time.Second); !f.Now().Equal(want) {
		t.Fatalf("Now() = %v, quer %v", f.Now(), want)
	}
}

func TestFakeTimerFiresAtDeadlineNotBefore(t *testing.T) {
	f := NewFake(t0)
	tm := f.NewTimer(10 * time.Second)

	f.Advance(9 * time.Second)
	if _, ok := received(tm.C()); ok {
		t.Fatal("timer disparou antes do prazo")
	}
	f.Advance(time.Second)
	v, ok := received(tm.C())
	if !ok {
		t.Fatal("timer não disparou no prazo")
	}
	if want := t0.Add(10 * time.Second); !v.Equal(want) {
		t.Fatalf("valor do timer = %v, quer %v", v, want)
	}
	if f.Waiters() != 0 {
		t.Fatalf("Waiters() = %d depois de disparar, quer 0", f.Waiters())
	}
}

func TestFakeTimersFireInDeadlineOrder(t *testing.T) {
	f := NewFake(t0)
	late := f.NewTimer(5 * time.Second)
	early := f.NewTimer(2 * time.Second)

	f.Advance(10 * time.Second)
	e, _ := received(early.C())
	l, _ := received(late.C())
	if !e.Before(l) {
		t.Fatalf("ordem errada: early=%v late=%v", e, l)
	}
}

func TestFakeStopPreventsFiring(t *testing.T) {
	f := NewFake(t0)
	tm := f.NewTimer(time.Second)
	if !tm.Stop() {
		t.Fatal("Stop() = false em timer ativo")
	}
	f.Advance(time.Hour)
	if _, ok := received(tm.C()); ok {
		t.Fatal("timer parado disparou")
	}
	if tm.Stop() {
		t.Fatal("Stop() = true em timer já parado")
	}
}

func TestFakeResetDropsStaleValue(t *testing.T) {
	f := NewFake(t0)
	tm := f.NewTimer(time.Second)
	f.Advance(time.Second) // dispara e deixa valor no canal

	if tm.Reset(5 * time.Second) {
		t.Fatal("Reset() = true em timer que já tinha disparado")
	}
	if _, ok := received(tm.C()); ok {
		t.Fatal("Reset deixou valor antigo no canal")
	}
	f.Advance(5 * time.Second)
	if _, ok := received(tm.C()); !ok {
		t.Fatal("timer reiniciado não disparou")
	}
}

func TestFakeZeroDurationFiresImmediately(t *testing.T) {
	f := NewFake(t0)
	if _, ok := received(f.After(0)); !ok {
		t.Fatal("After(0) não disparou imediatamente")
	}
}

func TestFakeSetBackwardsPanics(t *testing.T) {
	f := NewFake(t0)
	defer func() {
		if recover() == nil {
			t.Fatal("Set para o passado não gerou panic")
		}
	}()
	f.Set(t0.Add(-time.Second))
}

func TestBlockUntilWaitersSyncsWithGoroutine(t *testing.T) {
	f := NewFake(t0)
	done := make(chan time.Time)
	go func() { done <- <-f.After(30 * time.Second) }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := f.BlockUntilWaiters(ctx, 1); err != nil {
		t.Fatalf("BlockUntilWaiters: %v", err)
	}
	f.Advance(30 * time.Second)

	select {
	case v := <-done:
		if want := t0.Add(30 * time.Second); !v.Equal(want) {
			t.Fatalf("goroutine recebeu %v, quer %v", v, want)
		}
	case <-ctx.Done():
		t.Fatal("goroutine não acordou")
	}
}

func TestBlockUntilWaitersRespectsContext(t *testing.T) {
	f := NewFake(t0)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := f.BlockUntilWaiters(ctx, 1); err == nil {
		t.Fatal("esperava erro de contexto cancelado")
	}
}

func TestRealClockSatisfiesInterface(t *testing.T) {
	c := Real()
	tm := c.NewTimer(time.Hour)
	if !tm.Stop() {
		t.Fatal("Stop() = false em timer real ativo")
	}
	if c.Now().IsZero() {
		t.Fatal("Now() real devolveu zero")
	}
}
