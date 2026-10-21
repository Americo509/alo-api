// Package clock abstrai o tempo para que a lógica de negócio seja testável sem
// time.Sleep. Código de produção recebe um Clock; testes usam Fake e avançam o
// tempo explicitamente (docs/CONVENCOES.md).
package clock

import "time"

// Clock é a única fonte de tempo permitida fora deste pacote (o lint proíbe
// time.Now e time.Sleep no resto do código).
type Clock interface {
	Now() time.Time
	After(d time.Duration) <-chan time.Time
	NewTimer(d time.Duration) Timer
}

// Timer segue a semântica de time.Timer a partir do Go 1.23: depois de Stop ou
// Reset, nenhum valor antigo é recebido do canal.
type Timer interface {
	C() <-chan time.Time
	Stop() bool
	Reset(d time.Duration) bool
}

// Real devolve o relógio do sistema.
func Real() Clock { return realClock{} }

type realClock struct{}

func (realClock) Now() time.Time                         { return time.Now() }
func (realClock) After(d time.Duration) <-chan time.Time { return time.After(d) }
func (realClock) NewTimer(d time.Duration) Timer         { return &realTimer{t: time.NewTimer(d)} }

type realTimer struct{ t *time.Timer }

func (r *realTimer) C() <-chan time.Time        { return r.t.C }
func (r *realTimer) Stop() bool                 { return r.t.Stop() }
func (r *realTimer) Reset(d time.Duration) bool { return r.t.Reset(d) }
