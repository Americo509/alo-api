package mailer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Americo509/alo-api/internal/clock"
	"github.com/Americo509/alo-api/internal/crypto/envelope"
	"github.com/Americo509/alo-api/internal/crypto/envelope/envelopetest"
)

// fakeSender registra e pode falhar de forma controlada.
type fakeSender struct {
	mu    sync.Mutex
	sent  []Message
	calls int
	err   error
}

func (f *fakeSender) Send(_ context.Context, m Message) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return f.err
	}
	f.sent = append(f.sent, m)
	return nil
}

func (f *fakeSender) setErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

type fixture struct {
	mailer *OutboxMailer
	disp   *Dispatcher
	ob     *MemoryOutbox
	sender *fakeSender
	clk    *clock.Fake
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	clk := clock.NewFake(t0)
	key, _, err := envelope.New(envelopetest.New()).GenerateKey(ctx)
	if err != nil {
		t.Fatal(err)
	}
	ob := NewMemoryOutbox()
	om, err := NewOutboxMailer(ob, key, tpl(t), clk)
	if err != nil {
		t.Fatal(err)
	}
	snd := &fakeSender{}
	disp, err := NewDispatcher(ob, key, snd, clk, DefaultDispatcherConfig(), nil)
	if err != nil {
		t.Fatal(err)
	}
	disp.jitter = func() float64 { return 1 } // backoff previsível nos testes
	return &fixture{mailer: om, disp: disp, ob: ob, sender: snd, clk: clk}
}

func TestQueuedContentIsEncrypted(t *testing.T) {
	f := newFixture(t)
	if err := f.mailer.SendPasswordRecovery(ctx, rcptAddr, tokenSecret); err != nil {
		t.Fatal(err)
	}
	if f.ob.Pending() != 1 {
		t.Fatalf("itens na fila = %d", f.ob.Pending())
	}
	for _, p := range f.ob.Payloads() {
		for _, secret := range []string{tokenSecret, rcptAddr, "Redefinir", "reset-password"} {
			if bytes.Contains(p, []byte(secret)) {
				t.Errorf("o conteúdo da fila contém %q em claro", secret)
			}
		}
	}
}

func TestDispatchSendsAndRemoves(t *testing.T) {
	f := newFixture(t)
	_ = f.mailer.SendEmailVerification(ctx, rcptAddr, tokenSecret)
	st, err := f.disp.RunOnce(ctx)
	if err != nil || st.Sent != 1 {
		t.Fatalf("RunOnce = %+v, %v", st, err)
	}
	if len(f.sender.sent) != 1 || f.sender.sent[0].To != rcptAddr {
		t.Fatalf("enviado: %+v", f.sender.sent)
	}
	if f.ob.Pending() != 0 {
		t.Fatal("item continua na fila depois de enviado")
	}
	// Uma segunda rodada não reenvia.
	if st, _ := f.disp.RunOnce(ctx); st.Sent != 0 {
		t.Fatalf("reenviou: %+v", st)
	}
}

func TestRetryWithExponentialBackoff(t *testing.T) {
	f := newFixture(t)
	f.sender.setErr(fmt.Errorf("%w: conexão", ErrSMTP))
	_ = f.mailer.SendEmailVerification(ctx, rcptAddr, tokenSecret)

	// Tentativa 1 falha; próxima só após 30 s (base), depois 60 s, depois 120 s.
	for i, wait := range []time.Duration{30 * time.Second, 60 * time.Second, 120 * time.Second} {
		st, _ := f.disp.RunOnce(ctx)
		if st.Retried != 1 {
			t.Fatalf("rodada %d: %+v", i, st)
		}
		// Antes do prazo, nada acontece.
		f.clk.Advance(wait - time.Second)
		if st, _ := f.disp.RunOnce(ctx); st.Retried+st.Sent+st.Dead != 0 {
			t.Fatalf("rodada %d: tentou antes do backoff de %v: %+v", i, wait, st)
		}
		f.clk.Advance(time.Second)
	}
	// Quando o provedor volta, o e-mail sai.
	f.sender.setErr(nil)
	if st, _ := f.disp.RunOnce(ctx); st.Sent != 1 {
		t.Fatalf("não enviou após o provedor voltar: %+v", st)
	}
}

func TestDeadAfterMaxAttemptsAndContentErased(t *testing.T) {
	f := newFixture(t)
	f.sender.setErr(fmt.Errorf("%w: conexão", ErrSMTP))
	_ = f.mailer.SendPasswordChanged(ctx, rcptAddr)

	for range DefaultDispatcherConfig().MaxAttempts {
		f.disp.RunOnce(ctx) //nolint:errcheck // estatística não importa aqui
		f.clk.Advance(2 * time.Hour)
	}
	if f.ob.DeadCount() != 1 || f.ob.Pending() != 0 {
		t.Fatalf("mortos=%d vivos=%d", f.ob.DeadCount(), f.ob.Pending())
	}
	for _, p := range f.ob.Payloads() {
		if len(p) != 0 {
			t.Error("o conteúdo do e-mail morto deveria ter sido apagado")
		}
	}
	calls := f.sender.calls
	f.disp.RunOnce(ctx) //nolint:errcheck // não deve mais tentar
	if f.sender.calls != calls {
		t.Fatal("tentou enviar um item morto")
	}
	// Mortos antigos são limpos.
	f.clk.Advance(8 * 24 * time.Hour)
	if n, _ := f.ob.PurgeDead(ctx, f.clk.Now().Add(-DefaultDispatcherConfig().DeadRetention)); n != 1 {
		t.Fatalf("PurgeDead removeu %d", n)
	}
}

func TestPermanentErrorIsNotRetried(t *testing.T) {
	f := newFixture(t)
	f.sender.setErr(fmt.Errorf("%w: destinatário", ErrInvalidMessage))
	_ = f.mailer.SendEmailVerification(ctx, rcptAddr, tokenSecret)
	st, _ := f.disp.RunOnce(ctx)
	if st.Dead != 1 || st.Retried != 0 {
		t.Fatalf("erro permanente: %+v", st)
	}
}

// Link de recuperação vencido não deve ser enviado.
func TestExpiredEmailIsDroppedNotSent(t *testing.T) {
	f := newFixture(t)
	_ = f.mailer.SendPasswordRecovery(ctx, rcptAddr, tokenSecret)
	f.clk.Advance(31 * time.Minute) // recuperação vale 30 min
	st, _ := f.disp.RunOnce(ctx)
	if st.Dropped != 1 || f.sender.calls != 0 {
		t.Fatalf("e-mail vencido: %+v, chamadas=%d", st, f.sender.calls)
	}
	if f.ob.Pending() != 0 {
		t.Fatal("item vencido continua na fila")
	}
}

// Dois despachantes ao mesmo tempo não enviam o mesmo e-mail duas vezes.
func TestConcurrentDispatchersDoNotDuplicate(t *testing.T) {
	f := newFixture(t)
	for i := range 20 {
		_ = f.mailer.SendEmailVerification(ctx, fmt.Sprintf("u%d@example.com", i), tokenSecret)
	}
	var wg sync.WaitGroup
	var sent atomic.Int32
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 5 {
				st, _ := f.disp.RunOnce(ctx)
				sent.Add(int32(st.Sent)) //nolint:gosec // pequeno
			}
		}()
	}
	wg.Wait()
	if sent.Load() != 20 || f.sender.calls != 20 {
		t.Fatalf("enviados=%d chamadas=%d, quer 20 (sem duplicar)", sent.Load(), f.sender.calls)
	}
}

// Um item que um despachante reservou e abandonou (caiu no meio) volta depois
// do lease.
func TestLeaseExpiresAfterCrash(t *testing.T) {
	f := newFixture(t)
	_ = f.mailer.SendEmailVerification(ctx, rcptAddr, tokenSecret)
	items, _ := f.ob.Claim(ctx, f.clk.Now(), 10, 2*time.Minute) // "despachante" que cai
	if len(items) != 1 {
		t.Fatal("não reservou")
	}
	if st, _ := f.disp.RunOnce(ctx); st.Sent != 0 {
		t.Fatal("enviou um item reservado por outro despachante")
	}
	f.clk.Advance(3 * time.Minute)
	if st, _ := f.disp.RunOnce(ctx); st.Sent != 1 {
		t.Fatal("o item não voltou depois do lease")
	}
}

// Um conteúdo trocado de lugar (AAD diferente) ou adulterado não é enviado.
func TestTamperedPayloadIsNotSent(t *testing.T) {
	f := newFixture(t)
	_ = f.mailer.SendEmailVerification(ctx, rcptAddr, tokenSecret)
	_ = f.mailer.SendEmailVerification(ctx, "outra@example.com", tokenSecret)
	// Troca os conteúdos entre as duas linhas.
	f.ob.mu.Lock()
	var rows []*row
	for _, r := range f.ob.rows {
		rows = append(rows, r)
	}
	rows[0].item.Payload, rows[1].item.Payload = rows[1].item.Payload, rows[0].item.Payload
	f.ob.mu.Unlock()

	st, _ := f.disp.RunOnce(ctx)
	if st.Sent != 0 || st.Dead != 2 || f.sender.calls != 0 {
		t.Fatalf("conteúdo trocado foi enviado: %+v chamadas=%d", st, f.sender.calls)
	}
}

func TestOutboxMailerRejectsBadRecipient(t *testing.T) {
	f := newFixture(t)
	for _, to := range []string{"", "x", "a@b.com\r\nBcc: v@x.com", "Nome <a@b.com>"} {
		if err := f.mailer.SendEmailVerification(ctx, to, tokenSecret); !errors.Is(err, ErrInvalidMessage) {
			t.Errorf("destinatário %q aceito: %v", to, err)
		}
	}
	if f.ob.Pending() != 0 {
		t.Fatal("algo foi para a fila")
	}
}

func TestNewDispatcherValidation(t *testing.T) {
	f := newFixture(t)
	good := DefaultDispatcherConfig()
	for name, mutate := range map[string]func(*DispatcherConfig){
		"lote zero":         func(c *DispatcherConfig) { c.Batch = 0 },
		"sem tentativas":    func(c *DispatcherConfig) { c.MaxAttempts = 0 },
		"backoff invertido": func(c *DispatcherConfig) { c.BackoffMax = time.Second },
		"poll zero":         func(c *DispatcherConfig) { c.Poll = 0 },
	} {
		cfg := good
		mutate(&cfg)
		if _, err := NewDispatcher(f.ob, f.disp.sealer, f.sender, f.clk, cfg, nil); err == nil {
			t.Errorf("%s: aceito", name)
		}
	}
	if _, err := NewDispatcher(nil, nil, nil, nil, good, nil); err == nil {
		t.Error("dependências ausentes aceitas")
	}
	_ = uuid.Nil
}

// Run termina quando o contexto é cancelado e processa a fila no caminho.
func TestRunStopsOnContextCancel(t *testing.T) {
	f := newFixture(t)
	_ = f.mailer.SendEmailVerification(ctx, rcptAddr, tokenSecret)
	cctx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- f.disp.Run(cctx) }()

	wctx, wcancel := context.WithTimeout(ctx, 5*time.Second)
	defer wcancel()
	if err := f.clk.BlockUntilWaiters(wctx, 1); err != nil {
		t.Fatalf("o loop não armou o timer: %v", err)
	}
	if f.sender.calls != 1 {
		t.Fatalf("a primeira rodada não enviou: chamadas=%d", f.sender.calls)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Run = %v", err)
		}
	case <-wctx.Done():
		t.Fatal("Run não terminou após cancelar")
	}
}
