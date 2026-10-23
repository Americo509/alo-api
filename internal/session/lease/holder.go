package lease

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/Americo509/alo-api/internal/clock"
)

// Manager adquire leases para um worker.
type Manager struct {
	backend Backend
	cfg     Config
	clock   clock.Clock
	owner   string
	log     *slog.Logger
}

// NewManager cria o gerenciador. owner identifica este worker (ex.: nome do
// pod + ID aleatório do processo).
func NewManager(b Backend, cfg Config, c clock.Clock, owner string, log *slog.Logger) (*Manager, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if owner == "" {
		return nil, fmt.Errorf("lease: owner vazio")
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Manager{backend: b, cfg: cfg, clock: c, owner: owner, log: log}, nil
}

// Acquire tenta assumir a instância. Em caso de sucesso, devolve um Holder que
// renova o lease em segundo plano até Release ou perda.
func (m *Manager) Acquire(ctx context.Context, instanceID string) (*Holder, error) {
	token, ok, err := m.backend.TryAcquire(ctx, instanceID, m.owner, m.cfg.TTL)
	if err != nil {
		return nil, fmt.Errorf("lease: adquirir %s: %w", instanceID, err)
	}
	if !ok {
		return nil, ErrHeld
	}
	now := m.clock.Now()
	h := &Holder{
		m:           m,
		fence:       Fence{InstanceID: instanceID, Owner: m.owner, Token: token, AcquiredAt: now},
		lost:        make(chan struct{}),
		stop:        make(chan struct{}),
		done:        make(chan struct{}),
		lastSuccess: now,
	}
	// A renovação sobrevive ao ctx de Acquire (que pode ser de uma requisição),
	// mas herda seus valores (ex.: trace). Termina por Release ou perda.
	go h.keep(context.WithoutCancel(ctx))
	return h, nil
}

// Holder representa uma posse ativa.
type Holder struct {
	m     *Manager
	fence Fence

	mu          sync.Mutex
	lastSuccess time.Time
	lostErr     error

	lost     chan struct{} // fechado quando a posse é perdida
	stop     chan struct{} // fechado por Release
	done     chan struct{} // fechado quando keep termina
	stopOnce sync.Once
}

// Fence devolve os dados da posse, incluindo o fencing token.
func (h *Holder) Fence() Fence { return h.fence }

// Lost é fechado quando a posse é perdida. O worker deve desconectar a sessão
// imediatamente ao receber.
func (h *Holder) Lost() <-chan struct{} { return h.lost }

// Err devolve o motivo da perda, ou nil se a posse ainda vale.
func (h *Holder) Err() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.lostErr
}

// WaitSafe espera o SafetyDelay antes de conectar (ADR-0005, item 5).
// Retorna ErrLost se a posse cair durante a espera.
func (h *Holder) WaitSafe(ctx context.Context) error {
	if h.m.cfg.SafetyDelay == 0 {
		return nil
	}
	t := h.m.clock.NewTimer(h.m.cfg.SafetyDelay)
	defer t.Stop()
	select {
	case <-t.C():
		return nil
	case <-h.lost:
		return ErrLost
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Release encerra a renovação e libera o lease. Seguro para chamar mais de uma vez.
func (h *Holder) Release(ctx context.Context) error {
	h.stopOnce.Do(func() { close(h.stop) })
	<-h.done
	if h.Err() != nil {
		return nil // já não somos donos; nada a liberar
	}
	if err := h.m.backend.Release(ctx, h.fence.InstanceID, h.fence.Owner); err != nil {
		return fmt.Errorf("lease: liberar %s: %w", h.fence.InstanceID, err)
	}
	return nil
}

func (h *Holder) keep(base context.Context) {
	defer close(h.done)
	cfg := h.m.cfg
	t := h.m.clock.NewTimer(cfg.RenewEvery)
	defer t.Stop()

	for {
		select {
		case <-h.stop:
			return
		case <-t.C():
		}

		ctx, cancel := context.WithTimeout(base, cfg.RenewEvery)
		ok, err := h.m.backend.Renew(ctx, h.fence.InstanceID, h.fence.Owner, cfg.TTL)
		cancel()
		now := h.m.clock.Now()

		switch {
		case err == nil && ok:
			h.mu.Lock()
			h.lastSuccess = now
			h.mu.Unlock()
		case err == nil && !ok:
			// O backend respondeu que não somos mais donos: perda certa.
			h.markLost(fmt.Errorf("%w: lease tomado ou expirado", ErrLost))
			return
		default:
			h.mu.Lock()
			since := now.Sub(h.lastSuccess)
			h.mu.Unlock()
			h.m.log.Warn("falha ao renovar lease",
				slog.String("instance_id", h.fence.InstanceID),
				slog.Duration("desde_ultima_renovacao", since),
				slog.Any("erro", err))
			if since >= cfg.GiveUpAfter {
				h.markLost(fmt.Errorf("%w: sem renovar há %s: %w", ErrLost, since, err))
				return
			}
		}

		// Depois de uma falha, tenta de novo antes: o prazo para desistir é curto.
		next := cfg.RenewEvery
		if err != nil {
			next = min(cfg.RenewEvery, cfg.GiveUpAfter/4)
		}
		t.Reset(next)
	}
}

func (h *Holder) markLost(err error) {
	h.mu.Lock()
	h.lostErr = err
	h.mu.Unlock()
	close(h.lost)
	h.m.log.Error("posse da instância perdida",
		slog.String("instance_id", h.fence.InstanceID),
		slog.Int64("fence", h.fence.Token),
		slog.Any("erro", err))
}
