package mailer

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/smtp"
	"time"

	"github.com/Americo509/alo-api/internal/clock"
)

// Sender entrega uma mensagem (SMTP em produção).
type Sender interface {
	Send(ctx context.Context, m Message) error
}

// TLSMode define como a conexão SMTP é protegida.
type TLSMode string

const (
	// TLSImplicit: TLS desde o início da conexão (porta 465).
	TLSImplicit TLSMode = "implicit"
	// TLSStartTLS: conexão em texto que DEVE subir para TLS antes de qualquer
	// credencial ou mensagem (portas 587/25). Se o servidor não oferecer STARTTLS,
	// o envio é recusado (nunca cai para texto puro).
	TLSStartTLS TLSMode = "starttls"
	// TLSNone: sem TLS. Só aceito para localhost (desenvolvimento, MailHog).
	TLSNone TLSMode = "none"
)

// SMTPConfig configura o remetente. O Password nunca é logado nem incluído em
// erros.
type SMTPConfig struct {
	Addr     string // host:porta
	Mode     TLSMode
	Username string
	Password string
	From     string // endereço de envio (ex.: nao-responda@exemplo.com.br)
	FromName string // nome de exibição (ex.: "Alô API")
	// TLSConfig opcional (ex.: RootCAs em testes). ServerName e MinVersion são
	// sempre ajustados aqui.
	TLSConfig *tls.Config
	Timeout   time.Duration
}

// SMTPSender envia por SMTP.
type SMTPSender struct {
	cfg   SMTPConfig
	host  string
	from  *mail.Address
	clock clock.Clock
}

// ErrSMTP encapsula falhas de envio sem vazar credenciais nem o destinatário.
var ErrSMTP = errors.New("mailer: falha no envio SMTP")

// NewSMTPSender valida a configuração.
func NewSMTPSender(cfg SMTPConfig, clk clock.Clock) (*SMTPSender, error) {
	host, _, err := net.SplitHostPort(cfg.Addr)
	if err != nil || host == "" {
		return nil, fmt.Errorf("mailer: Addr inválido %q (use host:porta)", cfg.Addr)
	}
	switch cfg.Mode {
	case TLSImplicit, TLSStartTLS:
	case TLSNone:
		if !isLoopback(host) {
			return nil, errors.New("mailer: TLSNone só é permitido para localhost")
		}
	default:
		return nil, fmt.Errorf("mailer: modo TLS desconhecido %q", cfg.Mode)
	}
	fromAddr, err := ParseRecipient(cfg.From)
	if err != nil {
		return nil, errors.New("mailer: endereço de origem inválido")
	}
	if hasControl(cfg.FromName) || hasControl(cfg.Username) {
		return nil, errors.New("mailer: caracteres inválidos na configuração")
	}
	if clk == nil {
		return nil, errors.New("mailer: Clock obrigatório")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	return &SMTPSender{
		cfg: cfg, host: host, clock: clk,
		from: &mail.Address{Name: cfg.FromName, Address: fromAddr.Address},
	}, nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (s *SMTPSender) tlsConfig() *tls.Config {
	var c *tls.Config
	if s.cfg.TLSConfig != nil {
		c = s.cfg.TLSConfig.Clone()
	} else {
		c = &tls.Config{}
	}
	c.ServerName = s.host
	c.MinVersion = tls.VersionTLS12
	return c
}

// Send valida, monta e entrega a mensagem. Os erros devolvidos não contêm a
// senha nem o endereço do destinatário.
func (s *SMTPSender) Send(ctx context.Context, m Message) error {
	to, err := m.validate()
	if err != nil {
		return err
	}
	raw, err := build(s.from, to, m, s.clock.Now(), nil)
	if err != nil {
		return fmt.Errorf("%w: montar mensagem", ErrSMTP)
	}
	if err := s.deliver(ctx, to.Address, raw); err != nil {
		return err
	}
	return nil
}

func (s *SMTPSender) deliver(ctx context.Context, rcpt string, raw []byte) error {
	deadline := time.Now().Add(s.cfg.Timeout) //nolint:forbidigo // prazo de rede real, não lógica de negócio
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	dialer := &net.Dialer{Deadline: deadline}
	conn, err := dialer.DialContext(ctx, "tcp", s.cfg.Addr)
	if err != nil {
		return fmt.Errorf("%w: conexão", ErrSMTP)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(deadline)

	if s.cfg.Mode == TLSImplicit {
		tc := tls.Client(conn, s.tlsConfig())
		if err := tc.HandshakeContext(ctx); err != nil {
			return fmt.Errorf("%w: handshake TLS", ErrSMTP)
		}
		conn = tc
	}
	c, err := smtp.NewClient(conn, s.host)
	if err != nil {
		return fmt.Errorf("%w: saudação", ErrSMTP)
	}
	defer func() { _ = c.Close() }()

	if s.cfg.Mode == TLSStartTLS {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return fmt.Errorf("%w: servidor não oferece STARTTLS (envio recusado)", ErrSMTP)
		}
		if err := c.StartTLS(s.tlsConfig()); err != nil {
			return fmt.Errorf("%w: STARTTLS", ErrSMTP)
		}
	}
	if s.cfg.Username != "" {
		// PlainAuth se recusa a enviar a senha por conexão sem TLS (exceto localhost).
		if err := c.Auth(smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, s.host)); err != nil {
			return fmt.Errorf("%w: autenticação", ErrSMTP)
		}
	}
	if err := c.Mail(s.from.Address); err != nil {
		return fmt.Errorf("%w: remetente recusado", ErrSMTP)
	}
	if err := c.Rcpt(rcpt); err != nil {
		return fmt.Errorf("%w: destinatário recusado", ErrSMTP)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("%w: DATA", ErrSMTP)
	}
	if _, err := w.Write(raw); err != nil {
		return fmt.Errorf("%w: escrita", ErrSMTP)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("%w: fim dos dados", ErrSMTP)
	}
	_ = c.Quit()
	return nil
}

// Permanent informa se o erro SMTP é definitivo (não adianta tentar de novo).
// O texto do erro foi removido por segurança; aqui só reconhecemos os casos em
// que repetir é inútil: mensagem inválida.
func Permanent(err error) bool { return errors.Is(err, ErrInvalidMessage) }
