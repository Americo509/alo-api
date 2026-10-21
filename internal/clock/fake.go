package clock

import (
	"context"
	"slices"
	"sync"
	"time"
)

// Fake é um relógio controlado pelo teste. O tempo só anda com Advance ou Set.
// É seguro para uso concorrente.
type Fake struct {
	mu      sync.Mutex
	now     time.Time
	timers  []*fakeTimer
	changed chan struct{} // fechado e substituído a cada mudança no conjunto de timers
}

// NewFake cria um relógio parado em start.
func NewFake(start time.Time) *Fake {
	return &Fake{now: start, changed: make(chan struct{})}
}

func (f *Fake) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

func (f *Fake) After(d time.Duration) <-chan time.Time { return f.NewTimer(d).C() }

func (f *Fake) NewTimer(d time.Duration) Timer {
	f.mu.Lock()
	defer f.mu.Unlock()
	t := &fakeTimer{clock: f, c: make(chan time.Time, 1)}
	f.scheduleLocked(t, d)
	return t
}

// Advance move o relógio para frente e dispara, em ordem de prazo, todos os
// timers vencidos.
func (f *Fake) Advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.setLocked(f.now.Add(d))
}

// Set move o relógio para t. Voltar no tempo é proibido: relógio monotônico.
func (f *Fake) Set(t time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if t.Before(f.now) {
		panic("clock.Fake: Set para um instante anterior ao atual")
	}
	f.setLocked(t)
}

// Waiters devolve quantos timers estão ativos.
func (f *Fake) Waiters() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.timers)
}

// BlockUntilWaiters espera até haver pelo menos n timers ativos. Usado para
// sincronizar o teste com goroutines antes de chamar Advance.
func (f *Fake) BlockUntilWaiters(ctx context.Context, n int) error {
	for {
		f.mu.Lock()
		if len(f.timers) >= n {
			f.mu.Unlock()
			return nil
		}
		ch := f.changed
		f.mu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (f *Fake) setLocked(t time.Time) {
	f.now = t
	slices.SortStableFunc(f.timers, func(a, b *fakeTimer) int { return a.deadline.Compare(b.deadline) })
	kept := f.timers[:0:0]
	fired := false
	for _, tm := range f.timers {
		if tm.deadline.After(f.now) {
			kept = append(kept, tm)
			continue
		}
		tm.fireLocked()
		fired = true
	}
	f.timers = kept
	if fired {
		f.notifyLocked()
	}
}

func (f *Fake) scheduleLocked(t *fakeTimer, d time.Duration) {
	t.deadline = f.now.Add(d)
	if d <= 0 {
		t.fireLocked()
		return
	}
	f.timers = append(f.timers, t)
	f.notifyLocked()
}

func (f *Fake) removeLocked(t *fakeTimer) bool {
	i := slices.Index(f.timers, t)
	if i < 0 {
		return false
	}
	f.timers = slices.Delete(f.timers, i, i+1)
	f.notifyLocked()
	return true
}

func (f *Fake) notifyLocked() {
	close(f.changed)
	f.changed = make(chan struct{})
}

type fakeTimer struct {
	clock    *Fake
	c        chan time.Time
	deadline time.Time
}

func (t *fakeTimer) C() <-chan time.Time { return t.c }

func (t *fakeTimer) Stop() bool {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	t.drain()
	return t.clock.removeLocked(t)
}

func (t *fakeTimer) Reset(d time.Duration) bool {
	t.clock.mu.Lock()
	defer t.clock.mu.Unlock()
	active := t.clock.removeLocked(t)
	t.drain()
	t.clock.scheduleLocked(t, d)
	return active
}

func (t *fakeTimer) fireLocked() {
	select {
	case t.c <- t.deadline:
	default:
	}
}

func (t *fakeTimer) drain() {
	select {
	case <-t.c:
	default:
	}
}
