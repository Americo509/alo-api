package mailer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"time"

	"github.com/google/uuid"

	"github.com/Americo509/alo-api/internal/clock"
)

// Kind classifica o e-mail (para validade e métricas).
type Kind string

//nolint:gosec // G101: rótulos de tipo de e-mail, não credenciais
const (
	KindVerification    Kind = "verificacao_email"
	KindRecovery        Kind = "recuperacao_senha"
	KindPasswordChanged Kind = "senha_alterada"
	KindAccountExists   Kind = "conta_existente"
	KindInvitation      Kind = "convite_tenant"
)

// Sealer cifra o conteúdo na fila: o e-mail carrega links com tokens, então
// não pode ficar em claro no banco (ver ADR-0007, item 3). Em produção é a
// chave de dados da plataforma (envelope.DataKey).
type Sealer interface {
	Seal(plaintext, aad []byte) ([]byte, error)
	Open(sealed, aad []byte) ([]byte, error)
}

func aad(id uuid.UUID) []byte { return append([]byte("mail-outbox:"), id[:]...) }

// Item é uma linha da fila.
type Item struct {
	ID        uuid.UUID
	Kind      Kind
	Payload   []byte // JSON da Message, cifrado
	Attempts  int    // já contando a tentativa em andamento (após Claim)
	ExpiresAt time.Time
}

// Outbox é a fila durável de e-mails (Postgres em produção).
type Outbox interface {
	Enqueue(ctx context.Context, it Item, availableAt time.Time) error
	// Claim reserva até limit itens prontos por lease, incrementando as tentativas.
	// Dois dispatchers nunca recebem o mesmo item enquanto o lease vale.
	Claim(ctx context.Context, now time.Time, limit int, lease time.Duration) ([]Item, error)
	// Done remove o item (enviado ou descartado por expiração).
	Done(ctx context.Context, id uuid.UUID) error
	// Retry reagenda o item.
	Retry(ctx context.Context, id uuid.UUID, next time.Time, errClass string) error
	// Dead marca o item como falho definitivo e apaga o conteúdo.
	Dead(ctx context.Context, id uuid.UUID, now time.Time, errClass string) error
	// PurgeDead apaga os itens mortos mais antigos que olderThan.
	PurgeDead(ctx context.Context, olderThan time.Time) (int64, error)
}

type payload struct {
	To      string `json:"to"`
	Subject string `json:"s"`
	Text    string `json:"t"`
	HTML    string `json:"h"`
}

// OutboxMailer implementa authflow.Mailer gravando na fila. Gravar é rápido e
// independe do provedor de e-mail, então o tempo de resposta da API não revela
// se a conta existe.
type OutboxMailer struct {
	ob     Outbox
	sealer Sealer
	tpl    Templates
	clock  clock.Clock
}

// NewOutboxMailer cria o Mailer.
func NewOutboxMailer(ob Outbox, sealer Sealer, tpl Templates, clk clock.Clock) (*OutboxMailer, error) {
	if ob == nil || sealer == nil || clk == nil || tpl.baseURL == "" {
		return nil, errors.New("mailer: dependências obrigatórias ausentes")
	}
	return &OutboxMailer{ob: ob, sealer: sealer, tpl: tpl, clock: clk}, nil
}

func (m *OutboxMailer) enqueue(ctx context.Context, kind Kind, to string, r Rendered, validity time.Duration) error {
	if _, err := ParseRecipient(to); err != nil {
		return err
	}
	id := uuid.New()
	raw, err := json.Marshal(payload{To: to, Subject: r.Subject, Text: r.Text, HTML: r.HTML})
	if err != nil {
		return err
	}
	sealed, err := m.sealer.Seal(raw, aad(id))
	clear(raw)
	if err != nil {
		return fmt.Errorf("mailer: cifrar mensagem: %w", err)
	}
	now := m.clock.Now()
	return m.ob.Enqueue(ctx, Item{ID: id, Kind: kind, Payload: sealed, ExpiresAt: now.Add(validity)}, now)
}

// SendEmailVerification implementa authflow.Mailer.
func (m *OutboxMailer) SendEmailVerification(ctx context.Context, to, token string) error {
	r, err := m.tpl.EmailVerification(token)
	if err != nil {
		return err
	}
	return m.enqueue(ctx, KindVerification, to, r, VerificationValidity)
}

// SendPasswordRecovery implementa authflow.Mailer.
func (m *OutboxMailer) SendPasswordRecovery(ctx context.Context, to, token string) error {
	r, err := m.tpl.PasswordRecovery(token)
	if err != nil {
		return err
	}
	return m.enqueue(ctx, KindRecovery, to, r, RecoveryValidity)
}

// SendInvitation implementa tenant.Mailer.
func (m *OutboxMailer) SendInvitation(ctx context.Context, to, token, tenantName string) error {
	r, err := m.tpl.Invitation(token, tenantName)
	if err != nil {
		return err
	}
	return m.enqueue(ctx, KindInvitation, to, r, InvitationValidity)
}

// SendPasswordChanged implementa authflow.Mailer.
func (m *OutboxMailer) SendPasswordChanged(ctx context.Context, to string) error {
	r, err := m.tpl.PasswordChanged()
	if err != nil {
		return err
	}
	return m.enqueue(ctx, KindPasswordChanged, to, r, 24*time.Hour)
}

// SendAccountExists implementa authflow.Mailer.
func (m *OutboxMailer) SendAccountExists(ctx context.Context, to string) error {
	r, err := m.tpl.AccountExists()
	if err != nil {
		return err
	}
	return m.enqueue(ctx, KindAccountExists, to, r, 24*time.Hour)
}

// --- despachante ----------------------------------------------------------------

// DispatcherConfig ajusta o despachante. Valores iniciais conservadores.
type DispatcherConfig struct {
	Batch         int
	Lease         time.Duration // tempo reservado a um item em envio
	MaxAttempts   int
	BackoffBase   time.Duration
	BackoffMax    time.Duration
	Poll          time.Duration
	DeadRetention time.Duration // quanto tempo manter itens mortos (sem conteúdo) para diagnóstico
}

// DefaultDispatcherConfig devolve os valores padrão.
func DefaultDispatcherConfig() DispatcherConfig {
	return DispatcherConfig{
		Batch: 20, Lease: 2 * time.Minute, MaxAttempts: 8,
		BackoffBase: 30 * time.Second, BackoffMax: time.Hour,
		Poll: 2 * time.Second, DeadRetention: 7 * 24 * time.Hour,
	}
}

// Dispatcher lê a fila e entrega os e-mails.
type Dispatcher struct {
	ob     Outbox
	sealer Sealer
	sender Sender
	clock  clock.Clock
	cfg    DispatcherConfig
	log    *slog.Logger
	// jitter devolve um fator em [0.8, 1.2] aplicado ao backoff (injetável).
	jitter func() float64
}

// NewDispatcher cria o despachante.
func NewDispatcher(ob Outbox, sealer Sealer, sender Sender, clk clock.Clock, cfg DispatcherConfig, log *slog.Logger) (*Dispatcher, error) {
	if ob == nil || sealer == nil || sender == nil || clk == nil {
		return nil, errors.New("mailer: dependências obrigatórias ausentes")
	}
	if cfg.Batch < 1 || cfg.MaxAttempts < 1 || cfg.Lease <= 0 || cfg.BackoffBase <= 0 || cfg.BackoffMax < cfg.BackoffBase || cfg.Poll <= 0 {
		return nil, errors.New("mailer: configuração do despachante inválida")
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Dispatcher{
		ob: ob, sealer: sealer, sender: sender, clock: clk, cfg: cfg, log: log,
		jitter: func() float64 { return 0.8 + rand.Float64()*0.4 }, //nolint:gosec // jitter não é criptográfico
	}, nil
}

// Stats resume uma rodada.
type Stats struct{ Sent, Retried, Dead, Dropped int }

func (d *Dispatcher) backoff(attempts int) time.Duration {
	b := d.cfg.BackoffBase
	for i := 1; i < attempts && b < d.cfg.BackoffMax; i++ {
		b *= 2
	}
	b = min(b, d.cfg.BackoffMax)
	return time.Duration(float64(b) * d.jitter())
}

// RunOnce processa um lote. Os erros de itens individuais viram retry/dead; só
// falhas da própria fila são devolvidas.
func (d *Dispatcher) RunOnce(ctx context.Context) (Stats, error) {
	var st Stats
	now := d.clock.Now()
	items, err := d.ob.Claim(ctx, now, d.cfg.Batch, d.cfg.Lease)
	if err != nil {
		return st, fmt.Errorf("mailer: reservar itens: %w", err)
	}
	for _, it := range items {
		if !now.Before(it.ExpiresAt) {
			// Link de recuperação vencido não adianta enviar.
			if err := d.ob.Done(ctx, it.ID); err != nil {
				return st, err
			}
			st.Dropped++
			d.log.Info("e-mail descartado por expiração", slog.String("tipo", string(it.Kind)))
			continue
		}
		raw, err := d.sealer.Open(it.Payload, aad(it.ID))
		var msg payload
		if err == nil {
			err = json.Unmarshal(raw, &msg)
		}
		if err != nil {
			if derr := d.ob.Dead(ctx, it.ID, now, "conteudo_ilegivel"); derr != nil {
				return st, derr
			}
			st.Dead++
			d.log.Error("e-mail ilegível na fila", slog.String("tipo", string(it.Kind)))
			continue
		}
		sendErr := d.sender.Send(ctx, Message(msg))
		clear(raw)
		switch {
		case sendErr == nil:
			if err := d.ob.Done(ctx, it.ID); err != nil {
				return st, err
			}
			st.Sent++
		case Permanent(sendErr) || it.Attempts >= d.cfg.MaxAttempts:
			if err := d.ob.Dead(ctx, it.ID, now, errClass(sendErr)); err != nil {
				return st, err
			}
			st.Dead++
			d.log.Error("e-mail falhou em definitivo",
				slog.String("tipo", string(it.Kind)), slog.Int("tentativas", it.Attempts))
		default:
			if err := d.ob.Retry(ctx, it.ID, now.Add(d.backoff(it.Attempts)), errClass(sendErr)); err != nil {
				return st, err
			}
			st.Retried++
			d.log.Warn("falha ao enviar e-mail; nova tentativa agendada",
				slog.String("tipo", string(it.Kind)), slog.Int("tentativa", it.Attempts))
		}
	}
	return st, nil
}

// errClass reduz o erro a uma classe curta, SEM texto livre (que poderia
// conter o endereço do destinatário).
func errClass(err error) string {
	switch {
	case errors.Is(err, ErrInvalidMessage):
		return "mensagem_invalida"
	case errors.Is(err, ErrSMTP):
		return "smtp"
	default:
		return "desconhecido"
	}
}

// Run executa o despachante até o contexto terminar.
func (d *Dispatcher) Run(ctx context.Context) error {
	purgeEvery := time.Hour
	nextPurge := d.clock.Now().Add(purgeEvery)
	for {
		if _, err := d.RunOnce(ctx); err != nil && ctx.Err() == nil {
			d.log.Error("falha ao processar a fila de e-mails", slog.Any("erro", err))
		}
		if now := d.clock.Now(); !now.Before(nextPurge) {
			if _, err := d.ob.PurgeDead(ctx, now.Add(-d.cfg.DeadRetention)); err != nil && ctx.Err() == nil {
				d.log.Error("falha ao limpar e-mails mortos", slog.Any("erro", err))
			}
			nextPurge = now.Add(purgeEvery)
		}
		t := d.clock.NewTimer(d.cfg.Poll)
		select {
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		case <-t.C():
		}
	}
}
