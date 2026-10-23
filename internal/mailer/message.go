// Package mailer envia os e-mails transacionais da plataforma (verificação de
// e-mail, recuperação de senha, avisos de segurança) com segurança por padrão:
//
//   - SMTP com TLS OBRIGATÓRIO (implícito ou STARTTLS exigido; texto puro só
//     para localhost em desenvolvimento);
//   - validação rígida de destinatário e de cabeçalhos (sem injeção de CRLF);
//   - envio por fila (outbox) com o conteúdo CIFRADO em repouso, porque o
//     e-mail carrega links com tokens de uso único;
//   - links com o token no fragmento da URL (#token=...), que não vai para logs
//     de servidor nem para o Referer, e não é consumido por verificadores de
//     link de e-mail corporativo.
package mailer

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"strings"
	"time"
)

// Message é um e-mail pronto para envio.
type Message struct {
	To      string
	Subject string
	Text    string
	HTML    string
}

// crlf é o fim de linha de cabeçalhos SMTP/MIME (RFC 5322): CR (13) e LF (10).
const crlf = "\x0d\x0a"

// ErrInvalidMessage indica destinatário ou conteúdo recusado na validação.
var ErrInvalidMessage = errors.New("mailer: mensagem inválida")

// hasControl informa se s tem caracteres de controle (inclui CR e LF), que
// permitiriam injetar cabeçalhos.
func hasControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// ParseRecipient valida o destinatário: um único endereço, sem nome de exibição,
// sem caracteres de controle.
func ParseRecipient(raw string) (*mail.Address, error) {
	s := strings.TrimSpace(raw)
	if s == "" || len(s) > 254 || hasControl(s) {
		return nil, fmt.Errorf("%w: destinatário", ErrInvalidMessage)
	}
	addr, err := mail.ParseAddress(s)
	if err != nil || addr.Address != s || addr.Name != "" {
		return nil, fmt.Errorf("%w: destinatário", ErrInvalidMessage)
	}
	return addr, nil
}

func (m Message) validate() (*mail.Address, error) {
	to, err := ParseRecipient(m.To)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(m.Subject) == "" || hasControl(m.Subject) || len(m.Subject) > 200 {
		return nil, fmt.Errorf("%w: assunto", ErrInvalidMessage)
	}
	if m.Text == "" {
		return nil, fmt.Errorf("%w: corpo em texto é obrigatório", ErrInvalidMessage)
	}
	return to, nil
}

// build monta a mensagem MIME multipart/alternative (texto + HTML), com o
// conteúdo em quoted-printable e o assunto codificado (RFC 2047). As quebras de
// linha são CRLF (o multipart e o quoted-printable já escrevem assim).
func build(from, to *mail.Address, m Message, date time.Time, randRead func([]byte) (int, error)) ([]byte, error) {
	if randRead == nil {
		randRead = rand.Read
	}
	id := make([]byte, 16)
	if _, err := randRead(id); err != nil {
		return nil, err
	}
	domain := from.Address[strings.LastIndexByte(from.Address, '@')+1:]

	var body bytes.Buffer
	mp := multipart.NewWriter(&body)
	for _, p := range []struct{ ctype, text string }{
		{"text/plain; charset=UTF-8", m.Text},
		{"text/html; charset=UTF-8", m.HTML},
	} {
		if p.text == "" {
			continue
		}
		part, err := mp.CreatePart(textproto.MIMEHeader{
			"Content-Type":              {p.ctype},
			"Content-Transfer-Encoding": {"quoted-printable"},
		})
		if err != nil {
			return nil, err
		}
		qp := quotedprintable.NewWriter(part)
		if _, err := qp.Write([]byte(p.text)); err != nil {
			return nil, err
		}
		if err := qp.Close(); err != nil {
			return nil, err
		}
	}
	if err := mp.Close(); err != nil {
		return nil, err
	}

	var out bytes.Buffer
	hdr := func(k, v string) { fmt.Fprintf(&out, "%s: %s%s", k, v, crlf) }
	hdr("From", from.String())
	hdr("To", to.String())
	hdr("Subject", mime.QEncoding.Encode("utf-8", m.Subject))
	hdr("Date", date.UTC().Format(time.RFC1123Z))
	hdr("Message-ID", "<"+hex.EncodeToString(id)+"@"+domain+">")
	hdr("MIME-Version", "1.0")
	// Sinaliza mensagem automática: evita respostas automáticas e loops.
	hdr("Auto-Submitted", "auto-generated")
	hdr("X-Auto-Response-Suppress", "All")
	hdr("Content-Type", "multipart/alternative; boundary="+mp.Boundary())
	out.WriteString(crlf)
	out.Write(body.Bytes())
	return out.Bytes(), nil
}
