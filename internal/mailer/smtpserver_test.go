package mailer

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// smtpServer é um servidor SMTP mínimo de teste, com TLS implícito e STARTTLS.
type smtpServer struct {
	t  *testing.T
	ln net.Listener

	tlsCfg         *tls.Config
	pool           *x509.CertPool // confia no certificado do servidor
	implicit       bool           // TLS desde o início (porta 465)
	offerStartTLS  bool
	allowClearAuth bool // anuncia AUTH mesmo sem TLS (só para o teste de localhost)
	rejectRcpt     bool

	mu   sync.Mutex
	msgs []smtpReceived
	auth []string // "usuario:senha"
}

type smtpReceived struct {
	from, rcpt, data string
	overTLS          bool
}

// testCert gera um certificado autoassinado para 127.0.0.1/localhost e o pool
// que o confia.
func testCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "smtp-teste"},
		NotBefore:             time.Now().Add(-time.Hour), //nolint:forbidigo // validade do certificado de teste
		NotAfter:              time.Now().Add(time.Hour),  //nolint:forbidigo // validade do certificado de teste
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

func startSMTPWithPool(t *testing.T, cfg func(*smtpServer)) *smtpServer {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cert, pool := testCert(t)
	s := &smtpServer{t: t, ln: ln, pool: pool, tlsCfg: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}}
	if cfg != nil {
		cfg(s)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handle(c)
		}
	}()
	return s
}

func (s *smtpServer) addr() string { return s.ln.Addr().String() }

func (s *smtpServer) received() []smtpReceived {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]smtpReceived(nil), s.msgs...)
}

func (s *smtpServer) credentials() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.auth...)
}

func (s *smtpServer) handle(raw net.Conn) {
	defer func() { _ = raw.Close() }()
	conn := raw
	isTLS := false
	if s.implicit {
		tc := tls.Server(raw, s.tlsCfg)
		if tc.HandshakeContext(context.Background()) != nil {
			return
		}
		conn, isTLS = tc, true
	}
	br := bufio.NewReader(conn)
	say := func(format string, a ...any) { _, _ = fmt.Fprintf(conn, format+"\r\n", a...) }
	say("220 teste ESMTP")

	var from, rcpt string
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		up := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(up, "EHLO"), strings.HasPrefix(up, "HELO"):
			caps := []string{"teste"}
			if s.offerStartTLS && !isTLS {
				caps = append(caps, "STARTTLS")
			}
			if isTLS || s.allowClearAuth {
				caps = append(caps, "AUTH PLAIN")
			}
			caps = append(caps, "8BITMIME")
			for i, c := range caps {
				sep := "-"
				if i == len(caps)-1 {
					sep = " "
				}
				_, _ = fmt.Fprintf(conn, "250%s%s\r\n", sep, c)
			}
		case up == "STARTTLS":
			say("220 pode iniciar o TLS")
			tc := tls.Server(conn, s.tlsCfg)
			if tc.HandshakeContext(context.Background()) != nil {
				return
			}
			conn, br, isTLS = tc, bufio.NewReader(tc), true
		case strings.HasPrefix(up, "AUTH PLAIN"):
			parts := strings.Fields(line)
			if len(parts) < 3 {
				say("501 sintaxe")
				continue
			}
			b, _ := base64.StdEncoding.DecodeString(parts[2])
			f := bytes.Split(b, []byte{0})
			if len(f) == 3 {
				s.mu.Lock()
				s.auth = append(s.auth, string(f[1])+":"+string(f[2]))
				s.mu.Unlock()
			}
			say("235 autenticado")
		case strings.HasPrefix(up, "MAIL FROM:"):
			from = angle(line[len("MAIL FROM:"):])
			say("250 ok")
		case strings.HasPrefix(up, "RCPT TO:"):
			if s.rejectRcpt {
				say("550 usuário desconhecido")
				continue
			}
			rcpt = angle(line[len("RCPT TO:"):])
			say("250 ok")
		case up == "DATA":
			say("354 termine com <CRLF>.<CRLF>")
			var data strings.Builder
			for {
				l, err := br.ReadString('\n')
				if err != nil {
					return
				}
				if strings.TrimRight(l, "\r\n") == "." {
					break
				}
				data.WriteString(strings.TrimPrefix(l, ".")) // remove o dot-stuffing
			}
			s.mu.Lock()
			s.msgs = append(s.msgs, smtpReceived{from: from, rcpt: rcpt, data: data.String(), overTLS: isTLS})
			s.mu.Unlock()
			say("250 enfileirado")
		case up == "QUIT":
			say("221 tchau")
			return
		default:
			say("502 comando não suportado")
		}
	}
}

// angle extrai o endereço entre < e >, ignorando parâmetros como BODY=8BITMIME.
func angle(s string) string {
	a, b := strings.IndexByte(s, '<'), strings.IndexByte(s, '>')
	if a < 0 || b < a {
		return strings.TrimSpace(s)
	}
	return s[a+1 : b]
}
