package domain

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

var (
	t0 = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	t1 = t0.Add(time.Minute)
)

var allStatuses = []InstanceStatus{
	StatusDisconnected, StatusPairing, StatusConnected, StatusDegraded, StatusBanned,
}

var allEvents = []InstanceEvent{
	EventPairingStarted, EventPairingFailed, EventConnected, EventDisconnected,
	EventSessionInvalidated, EventRestrictionDetected, EventRestrictionCleared,
	EventBanned, EventBanLiftedAfterReview,
}

type start struct {
	status     InstanceStatus
	hasSession bool
	degraded   bool
}

func (s start) build() Instance {
	inst := Instance{Status: s.status, HasSession: s.hasSession, ChangedAt: t0}
	if s.degraded {
		d := t0
		inst.DegradedSince = &d
	}
	if s.status == StatusBanned {
		b := t0
		inst.BannedAt = &b
	}
	return inst
}

// Todas as combinações de estado inicial plausível. "degraded" só faz sentido
// em DEGRADADA ou em DESCONECTADA (queda enquanto degradada).
var allStarts = []start{
	{StatusDisconnected, false, false},
	{StatusDisconnected, true, false},
	{StatusDisconnected, true, true},
	{StatusPairing, false, false},
	{StatusConnected, true, false},
	{StatusDegraded, true, true},
	{StatusBanned, false, false},
}

type want struct {
	status     InstanceStatus
	hasSession bool
	degraded   bool
}

// Tabela-verdade completa: o que não estiver aqui tem de falhar.
var valid = map[start]map[InstanceEvent]want{
	{StatusDisconnected, false, false}: {
		EventPairingStarted: {StatusPairing, false, false},
		EventBanned:         {StatusBanned, false, false},
	},
	{StatusDisconnected, true, false}: {
		EventConnected:          {StatusConnected, true, false},
		EventSessionInvalidated: {StatusDisconnected, false, false},
		EventBanned:             {StatusBanned, false, false},
	},
	{StatusDisconnected, true, true}: {
		EventConnected:          {StatusDegraded, true, true},
		EventSessionInvalidated: {StatusDisconnected, false, true},
		EventBanned:             {StatusBanned, false, true},
	},
	{StatusPairing, false, false}: {
		EventPairingFailed: {StatusDisconnected, false, false},
		EventConnected:     {StatusConnected, true, false},
		EventBanned:        {StatusBanned, false, false},
	},
	{StatusConnected, true, false}: {
		EventDisconnected:        {StatusDisconnected, true, false},
		EventSessionInvalidated:  {StatusDisconnected, false, false},
		EventRestrictionDetected: {StatusDegraded, true, true},
		EventBanned:              {StatusBanned, false, false},
	},
	{StatusDegraded, true, true}: {
		EventDisconnected:       {StatusDisconnected, true, true},
		EventSessionInvalidated: {StatusDisconnected, false, true},
		EventRestrictionCleared: {StatusConnected, true, false},
		EventBanned:             {StatusBanned, false, true},
	},
	{StatusBanned, false, false}: {
		EventBanLiftedAfterReview: {StatusDisconnected, false, false},
	},
}

func TestApplyExhaustive(t *testing.T) {
	for _, s := range allStarts {
		for _, ev := range allEvents {
			name := fmt.Sprintf("%s/sessao=%t/degradada=%t/%s", s.status, s.hasSession, s.degraded, ev)
			t.Run(name, func(t *testing.T) {
				in := s.build()
				got, change, err := Apply(in, ev, t1)

				w, ok := valid[s][ev]
				if !ok {
					if !errors.Is(err, ErrInvalidTransition) {
						t.Fatalf("esperava ErrInvalidTransition, veio err=%v estado=%s", err, got.Status)
					}
					if got != in {
						t.Fatal("transição inválida alterou a instância")
					}
					return
				}
				if err != nil {
					t.Fatalf("erro inesperado: %v", err)
				}
				if got.Status != w.status || got.HasSession != w.hasSession || (got.DegradedSince != nil) != w.degraded {
					t.Fatalf("resultado = {%s sessao=%t degradada=%t}, quer {%s sessao=%t degradada=%t}",
						got.Status, got.HasSession, got.DegradedSince != nil, w.status, w.hasSession, w.degraded)
				}
				if change.From != s.status || change.To != w.status || change.Event != ev || !change.At.Equal(t1) {
					t.Fatalf("Change = %+v", change)
				}
				if !got.ChangedAt.Equal(t1) {
					t.Fatalf("ChangedAt = %v, quer %v", got.ChangedAt, t1)
				}
			})
		}
	}
}

func TestApplyDoesNotMutateInput(t *testing.T) {
	in := start{StatusConnected, true, false}.build()
	_, _, _ = Apply(in, EventRestrictionDetected, t1)
	if in.Status != StatusConnected || in.DegradedSince != nil {
		t.Fatal("Apply alterou a instância de entrada")
	}
}

func TestBanRecordsTimestampAndLiftClearsIt(t *testing.T) {
	inst, _, err := Apply(start{StatusConnected, true, false}.build(), EventBanned, t1)
	if err != nil || inst.BannedAt == nil || !inst.BannedAt.Equal(t1) {
		t.Fatalf("BannedAt = %v, err = %v", inst.BannedAt, err)
	}
	inst, _, err = Apply(inst, EventBanLiftedAfterReview, t1.Add(time.Hour))
	if err != nil || inst.BannedAt != nil {
		t.Fatalf("revisão não limpou BannedAt: %v, err = %v", inst.BannedAt, err)
	}
}

func TestFullLifecycle(t *testing.T) {
	steps := []struct {
		ev   InstanceEvent
		want InstanceStatus
	}{
		{EventPairingStarted, StatusPairing},
		{EventConnected, StatusConnected},
		{EventRestrictionDetected, StatusDegraded},
		{EventDisconnected, StatusDisconnected},
		{EventConnected, StatusDegraded}, // volta degradada
		{EventRestrictionCleared, StatusConnected},
		{EventSessionInvalidated, StatusDisconnected},
		{EventPairingStarted, StatusPairing},
	}
	inst := NewInstance(t0)
	at := t0
	for i, st := range steps {
		at = at.Add(time.Minute)
		var err error
		inst, _, err = Apply(inst, st.ev, at)
		if err != nil {
			t.Fatalf("passo %d (%s): %v", i, st.ev, err)
		}
		if inst.Status != st.want {
			t.Fatalf("passo %d (%s): estado %s, quer %s", i, st.ev, inst.Status, st.want)
		}
	}
}

func TestCanSendOnlyWhenConnected(t *testing.T) {
	for _, s := range allStatuses {
		got := Instance{Status: s}.CanSend()
		if got != (s == StatusConnected) {
			t.Errorf("CanSend() em %s = %t", s, got)
		}
	}
}
