package mailer

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"strings"
	"testing"
	"time"

	"github.com/Americo509/alo-api/internal/clock"
)

var (
	ctx = context.Background()
	t0  = time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
)

const (
	smtpPassword = "s3nha-Super-Secreta-do-SMTP"
	rcptAddr     = "ana.paciente@example.com"
)

func newSenderWithPool(t *testing.T, srv *smtpServer, mode TLSMode, trust bool) *SMTPSender {
	t.Helper()
	var tc *tls.Config
	if trust {
		tc = &tls.Config{RootCAs: srv.pool}
	}
	s, err := NewSMTPSender(SMTPConfig{
		Addr: srv.addr(), Mode: mode, Username: "usuario", Password: smtpPassword,
		From: "nao-responda@alo.example.com", FromName: "Alô API", TLSConfig: tc, Timeout: 5 * time.Second,
	}, clock.NewFake(t0))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func msg() Message {
	return Message{To: rcptAddr, Subject: "Confirme seu e-mail", Text: "Olá, ação necessária.\n.linha com ponto\n", HTML: "<p>Olá</p>"}
}

// decode abre a mensagem recebida e devolve as partes texto e HTML.
func decode(t *testing.T, raw string) (hdr mail.Header, text, html string) {
	t.Helper()
	m, err := mail.ReadMessage(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("mensagem ilegível: %v", err)
	}
	mt, params, err := mime.ParseMediaType(m.Header.Get("Content-Type"))
	if err != nil || mt != "multipart/alternative" {
		t.Fatalf("Content-Type = %q, %v", m.Header.Get("Content-Type"), err)
	}
	mr := multipart.NewReader(m.Body, params["boundary"])
	for {
		p, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(quotedprintable.NewReader(p))
		switch {
		case strings.HasPrefix(p.Header.Get("Content-Type"), "text/plain"):
			text = string(b)
		case strings.HasPrefix(p.Header.Get("Content-Type"), "text/html"):
			html = string(b)
		}
	}
	return m.Header, text, html
}

func TestSendImplicitTLS(t *testing.T) {
	srv := startSMTPWithPool(t, func(s *smtpServer) { s.implicit = true })
	if err := newSenderWithPool(t, srv, TLSImplicit, true).Send(ctx, msg()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	got := srv.received()
	if len(got) != 1 || !got[0].overTLS {
		t.Fatalf("mensagens = %+v", got)
	}
	if got[0].from != "nao-responda@alo.example.com" || got[0].rcpt != rcptAddr {
		t.Fatalf("envelope = %q -> %q", got[0].from, got[0].rcpt)
	}
	if c := srv.credentials(); len(c) != 1 || c[0] != "usuario:"+smtpPassword {
		t.Fatalf("credenciais recebidas = %v", c)
	}
	hdr, text, html := decode(t, got[0].data)
	if text != "Olá, ação necessária.\r\n.linha com ponto\r\n" && text != "Olá, ação necessária.\n.linha com ponto\n" {
		t.Errorf("texto = %q (acentos ou linha com ponto alterados)", text)
	}
	if html != "<p>Olá</p>" {
		t.Errorf("html = %q", html)
	}
	dec := new(mime.WordDecoder)
	if subj, _ := dec.DecodeHeader(hdr.Get("Subject")); subj != "Confirme seu e-mail" {
		t.Errorf("Subject = %q", subj)
	}
	if hdr.Get("Auto-Submitted") != "auto-generated" || !strings.HasSuffix(hdr.Get("Message-Id"), "@alo.example.com>") {
		t.Errorf("cabeçalhos: Auto-Submitted=%q Message-ID=%q", hdr.Get("Auto-Submitted"), hdr.Get("Message-Id"))
	}
	from, _ := mail.ParseAddress(hdr.Get("From"))
	if from == nil || from.Name != "Alô API" {
		t.Errorf("From = %q", hdr.Get("From"))
	}
}

func TestSendSTARTTLS(t *testing.T) {
	srv := startSMTPWithPool(t, func(s *smtpServer) { s.offerStartTLS = true })
	if err := newSenderWithPool(t, srv, TLSStartTLS, true).Send(ctx, msg()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	got := srv.received()
	if len(got) != 1 || !got[0].overTLS {
		t.Fatalf("a mensagem não foi entregue sobre TLS: %+v", got)
	}
	if c := srv.credentials(); len(c) != 1 {
		t.Fatalf("a autenticação deveria ocorrer depois do STARTTLS: %v", c)
	}
}

// Servidor que não oferece STARTTLS: o envio é RECUSADO, e nem a senha nem a
// mensagem trafegam em texto puro.
func TestStartTLSRequiredNeverFallsBackToPlaintext(t *testing.T) {
	srv := startSMTPWithPool(t, func(s *smtpServer) { s.offerStartTLS = false; s.allowClearAuth = true })
	err := newSenderWithPool(t, srv, TLSStartTLS, true).Send(ctx, msg())
	if !errors.Is(err, ErrSMTP) {
		t.Fatalf("esperava recusa, veio %v", err)
	}
	if len(srv.received()) != 0 || len(srv.credentials()) != 0 {
		t.Fatalf("vazou em texto puro: msgs=%d creds=%v", len(srv.received()), srv.credentials())
	}
}

// Certificado que o cliente não confia: o handshake falha e nada é enviado.
func TestUntrustedCertificateRejected(t *testing.T) {
	srv := startSMTPWithPool(t, func(s *smtpServer) { s.implicit = true })
	err := newSenderWithPool(t, srv, TLSImplicit, false).Send(ctx, msg()) // sem RootCAs de teste
	if !errors.Is(err, ErrSMTP) {
		t.Fatalf("certificado não confiável aceito: %v", err)
	}
	if len(srv.received()) != 0 || len(srv.credentials()) != 0 {
		t.Fatal("dados enviados a um servidor não verificado")
	}
}

func TestErrorsDoNotLeakSecretsOrRecipient(t *testing.T) {
	srv := startSMTPWithPool(t, func(s *smtpServer) { s.implicit = true; s.rejectRcpt = true })
	err := newSenderWithPool(t, srv, TLSImplicit, true).Send(ctx, msg())
	if !errors.Is(err, ErrSMTP) {
		t.Fatalf("esperava ErrSMTP: %v", err)
	}
	for _, secret := range []string{smtpPassword, rcptAddr, "usuario"} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("o erro vaza %q: %v", secret, err)
		}
	}
}

func TestTLSNoneOnlyForLoopback(t *testing.T) {
	clk := clock.NewFake(t0)
	base := SMTPConfig{Mode: TLSNone, From: "a@alo.example.com"}
	base.Addr = "smtp.exemplo.com:25"
	if _, err := NewSMTPSender(base, clk); err == nil {
		t.Fatal("TLSNone aceito para servidor remoto")
	}
	base.Addr = "127.0.0.1:1025"
	if _, err := NewSMTPSender(base, clk); err != nil {
		t.Fatalf("TLSNone recusado para localhost: %v", err)
	}
	base.Addr = "localhost:1025"
	if _, err := NewSMTPSender(base, clk); err != nil {
		t.Fatalf("TLSNone recusado para localhost: %v", err)
	}
}

func TestSenderConfigValidation(t *testing.T) {
	clk := clock.NewFake(t0)
	good := SMTPConfig{Addr: "smtp.exemplo.com:587", Mode: TLSStartTLS, From: "a@alo.example.com"}
	for name, mutate := range map[string]func(*SMTPConfig){
		"sem porta":        func(c *SMTPConfig) { c.Addr = "smtp.exemplo.com" },
		"modo inválido":    func(c *SMTPConfig) { c.Mode = "texto" },
		"from inválido":    func(c *SMTPConfig) { c.From = "nao-e-email" },
		"nome com CRLF":    func(c *SMTPConfig) { c.FromName = "Alô\r\nBcc: x@y.com" },
		"usuário com CRLF": func(c *SMTPConfig) { c.Username = "u\r\nx" },
	} {
		cfg := good
		mutate(&cfg)
		if _, err := NewSMTPSender(cfg, clk); err == nil {
			t.Errorf("%s: configuração inválida aceita", name)
		}
	}
	if _, err := NewSMTPSender(good, nil); err == nil {
		t.Error("sem relógio aceito")
	}
	if _, err := NewSMTPSender(good, clk); err != nil {
		t.Errorf("configuração válida recusada: %v", err)
	}
}

func TestSendRejectsHeaderInjection(t *testing.T) {
	srv := startSMTPWithPool(t, func(s *smtpServer) { s.implicit = true })
	snd := newSenderWithPool(t, srv, TLSImplicit, true)
	bad := []Message{
		{To: "a@b.com\r\nBcc: vitima@x.com", Subject: "x", Text: "t"},
		{To: "a@b.com\nBcc: vitima@x.com", Subject: "x", Text: "t"},
		{To: "Nome <a@b.com>", Subject: "x", Text: "t"},
		{To: "a@b.com, c@d.com", Subject: "x", Text: "t"},
		{To: "", Subject: "x", Text: "t"},
		{To: rcptAddr, Subject: "assunto\r\nBcc: vitima@x.com", Text: "t"},
		{To: rcptAddr, Subject: "", Text: "t"},
		{To: rcptAddr, Subject: "x", Text: ""},
	}
	for i, m := range bad {
		if err := snd.Send(ctx, m); !errors.Is(err, ErrInvalidMessage) {
			t.Errorf("caso %d aceito: %v", i, err)
		}
	}
	if len(srv.received()) != 0 {
		t.Fatal("alguma mensagem inválida foi entregue")
	}
}
