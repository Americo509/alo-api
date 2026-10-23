// Package loginguard protege o login contra força bruta e preenchimento de
// credenciais (ADR-0007, item 4): conta falhas por IP, por conta e global,
// impõe atraso progressivo e desafio anti-bot, e NUNCA bloqueia a conta em
// definitivo (isso viraria negação de serviço contra o usuário).
package loginguard

import (
	"context"
	"errors"
	"time"

	"github.com/Americo509/alo-api/internal/clock"
)

// Counter é um contador com janela de expiração (Redis em produção, memória em
// teste). Incr incrementa e devolve o valor atual; a janela é renovada a cada
// incremento (os contadores de falha "esfriam" após inatividade).
type Counter interface {
	Incr(ctx context.Context, key string, window time.Duration) (int64, error)
	Get(ctx context.Context, key string) (int64, error)
	Reset(ctx context.Context, keys ...string) error
}

// Decision é o veredito do guard para uma tentativa de login.
type Decision struct {
	// Allow: pode tentar autenticar agora.
	Allow bool
	// Delay: atraso artificial a aplicar antes de responder (ms a s), para
	// encarecer tentativa automatizada sem travar o usuário legítimo.
	Delay time.Duration
	// Challenge: exigir desafio anti-bot (CAPTCHA/prova de trabalho) nesta e
	// nas próximas tentativas até esfriar.
	Challenge bool
	// RetryAfter: quando Allow é false, quanto esperar.
	RetryAfter time.Duration
}

// Config define os limiares. Valores conservadores por padrão; calibráveis.
type Config struct {
	// Window: janela em que as falhas são contadas e após a qual esfriam.
	Window time.Duration
	// DelayAfter: a partir de tantas falhas por conta/IP, começa o atraso.
	DelayAfter int64
	// DelayStep: atraso somado por falha acima de DelayAfter (teto em MaxDelay).
	DelayStep time.Duration
	MaxDelay  time.Duration
	// ChallengeAfter: a partir de tantas falhas, exige desafio.
	ChallengeAfter int64
	// BlockAfter: a partir de tantas falhas por IP, recusa temporariamente
	// (RetryAfter). Por conta NÃO há bloqueio — só atraso e desafio.
	BlockAfterIP int64
	// GlobalWindow / GlobalStuffingThreshold: pico de falhas distribuídas na
	// janela curta liga o modo "sob ataque" (desafio para todos).
	GlobalWindow            time.Duration
	GlobalStuffingThreshold int64
}

// DefaultConfig devolve limiares iniciais conservadores.
func DefaultConfig() Config {
	return Config{
		Window:                  15 * time.Minute,
		DelayAfter:              3,
		DelayStep:               500 * time.Millisecond,
		MaxDelay:                5 * time.Second,
		ChallengeAfter:          5,
		BlockAfterIP:            50,
		GlobalWindow:            time.Minute,
		GlobalStuffingThreshold: 100,
	}
}

func (c Config) valid() error {
	switch {
	case c.Window <= 0 || c.GlobalWindow <= 0:
		return errors.New("loginguard: janelas devem ser positivas")
	case c.DelayAfter < 1 || c.ChallengeAfter < 1 || c.BlockAfterIP < 1:
		return errors.New("loginguard: limiares devem ser >= 1")
	case c.DelayStep < 0 || c.MaxDelay < 0:
		return errors.New("loginguard: atrasos não podem ser negativos")
	}
	return nil
}

// Guard aplica a política.
type Guard struct {
	c     Counter
	cfg   Config
	clock clock.Clock
}

// New cria o guard.
func New(c Counter, cfg Config, clk clock.Clock) (*Guard, error) {
	if err := cfg.valid(); err != nil {
		return nil, err
	}
	if c == nil || clk == nil {
		return nil, errors.New("loginguard: Counter e Clock são obrigatórios")
	}
	return &Guard{c: c, cfg: cfg, clock: clk}, nil
}

// Check decide se a tentativa pode prosseguir, lendo os contadores atuais.
// account é uma chave estável e não-PII da conta (ex.: hash do e-mail); ip é o
// endereço de origem.
func (g *Guard) Check(ctx context.Context, ip, account string) (Decision, error) {
	ipFails, err := g.c.Get(ctx, ipKey(ip))
	if err != nil {
		return Decision{}, err
	}
	acctFails, err := g.c.Get(ctx, acctKey(account))
	if err != nil {
		return Decision{}, err
	}
	globalFails, err := g.c.Get(ctx, globalKey)
	if err != nil {
		return Decision{}, err
	}

	// Bloqueio temporário só por IP (muitas falhas da mesma origem).
	if ipFails >= g.cfg.BlockAfterIP {
		return Decision{Allow: false, RetryAfter: g.cfg.Window}, nil
	}

	fails := max(ipFails, acctFails)
	d := Decision{Allow: true}
	if fails >= g.cfg.ChallengeAfter || globalFails >= g.cfg.GlobalStuffingThreshold {
		d.Challenge = true
	}
	if over := fails - g.cfg.DelayAfter; over >= 0 {
		d.Delay = min(g.cfg.DelayStep*time.Duration(over+1), g.cfg.MaxDelay)
	}
	return d, nil
}

// Fail registra uma tentativa malsucedida. Chamar depois de Check e da
// verificação de senha.
func (g *Guard) Fail(ctx context.Context, ip, account string) error {
	if _, err := g.c.Incr(ctx, ipKey(ip), g.cfg.Window); err != nil {
		return err
	}
	if _, err := g.c.Incr(ctx, acctKey(account), g.cfg.Window); err != nil {
		return err
	}
	_, err := g.c.Incr(ctx, globalKey, g.cfg.GlobalWindow)
	return err
}

// Success zera o contador da CONTA após um login bem-sucedido. O contador de IP
// NÃO é zerado: senão quem tem uma conta própria alternaria logins válidos para
// zerar o limite e continuar adivinhando senhas de outras contas. O IP e o
// global esfriam sozinhos pela janela.
func (g *Guard) Success(ctx context.Context, _, account string) error {
	return g.c.Reset(ctx, acctKey(account))
}

const globalKey = "lg:global"

func ipKey(ip string) string        { return "lg:ip:" + ip }
func acctKey(account string) string { return "lg:acct:" + account }
