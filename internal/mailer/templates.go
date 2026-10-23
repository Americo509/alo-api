package mailer

import (
	"bytes"
	"errors"
	"fmt"
	htmltemplate "html/template"
	"net/url"
	"strings"
	texttemplate "text/template"
	"time"
)

// Validade dos links, repetida no texto do e-mail. Deve acompanhar as validades
// do pacote authtoken (verificação 24 h, recuperação 30 min).
const (
	VerificationValidity = 24 * time.Hour
	RecoveryValidity     = 30 * time.Minute
)

// Templates monta os e-mails em português do Brasil.
type Templates struct {
	productName  string
	baseURL      string
	supportEmail string
}

// NewTemplates valida a configuração. baseURL é a origem do painel (https, sem
// barra final); em desenvolvimento aceita http://localhost.
func NewTemplates(productName, baseURL, supportEmail string) (Templates, error) {
	if strings.TrimSpace(productName) == "" || hasControl(productName) {
		return Templates{}, errors.New("mailer: nome do produto inválido")
	}
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" || u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.Fragment != "" {
		return Templates{}, fmt.Errorf("mailer: baseURL inválida %q (use só a origem)", baseURL)
	}
	loopback := u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1"
	if u.Scheme != "https" && (u.Scheme != "http" || !loopback) {
		return Templates{}, errors.New("mailer: baseURL deve usar https")
	}
	if supportEmail != "" {
		if _, err := ParseRecipient(supportEmail); err != nil {
			return Templates{}, errors.New("mailer: e-mail de suporte inválido")
		}
	}
	return Templates{
		productName:  strings.TrimSpace(productName),
		baseURL:      strings.TrimRight(u.Scheme+"://"+u.Host, "/"),
		supportEmail: supportEmail,
	}, nil
}

// Rendered é um e-mail já renderizado, sem destinatário.
type Rendered struct {
	Subject string
	Text    string
	HTML    string
}

// content é o que os modelos de texto e HTML recebem.
type content struct {
	Product    string
	Title      string
	Paragraphs []string
	Link       string
	Button     string
	Footer     string
}

// linkWithToken coloca o token no FRAGMENTO da URL: o navegador não o envia ao
// servidor (nem a logs, nem ao Referer), e verificadores de link não o consomem.
func (t Templates) linkWithToken(path, token string) string {
	return t.baseURL + path + "#token=" + url.QueryEscape(token)
}

func humanDuration(d time.Duration) string {
	if d >= time.Hour {
		h := int(d.Hours())
		if h == 1 {
			return "1 hora"
		}
		return fmt.Sprintf("%d horas", h)
	}
	return fmt.Sprintf("%d minutos", int(d.Minutes()))
}

// EmailVerification: confirmação de e-mail do cadastro.
func (t Templates) EmailVerification(token string) (Rendered, error) {
	return t.render(content{
		Title: "Confirme seu e-mail",
		Paragraphs: []string{
			fmt.Sprintf("Recebemos um cadastro no %s com este e-mail. Para ativar sua conta, confirme o endereço.", t.productName),
			fmt.Sprintf("Este link vale por %s e só pode ser usado uma vez.", humanDuration(VerificationValidity)),
		},
		Link:   t.linkWithToken("/auth/verify-email", token),
		Button: "Confirmar e-mail",
		Footer: "Se você não fez este cadastro, ignore esta mensagem: nenhuma conta será ativada.",
	}, "Confirme seu e-mail")
}

// PasswordRecovery: link para redefinir a senha.
func (t Templates) PasswordRecovery(token string) (Rendered, error) {
	return t.render(content{
		Title: "Redefinir sua senha",
		Paragraphs: []string{
			fmt.Sprintf("Recebemos um pedido para redefinir a senha da sua conta no %s.", t.productName),
			fmt.Sprintf("O link vale por %s e só pode ser usado uma vez.", humanDuration(RecoveryValidity)),
		},
		Link:   t.linkWithToken("/auth/reset-password", token),
		Button: "Redefinir senha",
		Footer: "Se você não fez este pedido, ignore esta mensagem: sua senha continua a mesma. Nunca compartilhe este link.",
	}, "Redefinir sua senha")
}

// PasswordChanged: aviso de segurança, sem link.
func (t Templates) PasswordChanged() (Rendered, error) {
	footer := "Se não foi você, redefina sua senha imediatamente"
	if t.supportEmail != "" {
		footer += " e fale com o suporte em " + t.supportEmail
	}
	return t.render(content{
		Title: "Sua senha foi alterada",
		Paragraphs: []string{
			fmt.Sprintf("A senha da sua conta no %s foi alterada agora há pouco.", t.productName),
			"Por segurança, as outras sessões abertas foram encerradas.",
		},
		Footer: footer + ".",
	}, "Sua senha foi alterada")
}

// AccountExists: resposta ao cadastro duplicado, enviada ao dono do e-mail, sem
// revelar nada a quem fez a requisição.
func (t Templates) AccountExists() (Rendered, error) {
	return t.render(content{
		Title: "Você já tem uma conta",
		Paragraphs: []string{
			fmt.Sprintf("Alguém tentou criar uma conta no %s com este e-mail, mas ela já existe.", t.productName),
			"Se foi você, é só entrar normalmente. Se esqueceu a senha, use a opção \"Esqueci minha senha\".",
		},
		Link:   t.baseURL + "/auth/login",
		Button: "Entrar",
		Footer: "Se não foi você, pode ignorar esta mensagem: nenhuma alteração foi feita na sua conta.",
	}, "Você já tem uma conta")
}

func (t Templates) render(c content, subject string) (Rendered, error) {
	c.Product = t.productName
	var txt, htm bytes.Buffer
	if err := textTmpl.Execute(&txt, c); err != nil {
		return Rendered{}, err
	}
	if err := htmlTmpl.Execute(&htm, c); err != nil {
		return Rendered{}, err
	}
	return Rendered{Subject: subject + " — " + t.productName, Text: txt.String(), HTML: htm.String()}, nil
}

var textTmpl = texttemplate.Must(texttemplate.New("text").Parse(`{{.Title}}

{{range .Paragraphs}}{{.}}

{{end}}{{if .Link}}{{.Button}}: {{.Link}}

{{end}}{{.Footer}}

— {{.Product}}
`))

var htmlTmpl = htmltemplate.Must(htmltemplate.New("html").Parse(`<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}}</title>
</head>
<body style="margin:0;padding:24px;background:#f4f5f7;font-family:-apple-system,'Segoe UI',Roboto,Arial,sans-serif;color:#1a1a1a">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0">
<tr><td align="center">
<table role="presentation" cellpadding="0" cellspacing="0" border="0" style="max-width:480px;width:100%;background:#ffffff;border-radius:8px">
<tr><td style="padding:32px">
<h1 style="font-size:20px;margin:0 0 16px">{{.Title}}</h1>
{{range .Paragraphs}}<p style="font-size:15px;line-height:1.5;margin:0 0 16px">{{.}}</p>
{{end}}{{if .Link}}<p style="margin:24px 0"><a href="{{.Link}}" style="background:#1a56db;color:#ffffff;text-decoration:none;padding:12px 20px;border-radius:6px;display:inline-block;font-weight:600">{{.Button}}</a></p>
<p style="font-size:13px;line-height:1.5;color:#555555;margin:0 0 16px">Se o botão não funcionar, copie e cole este endereço no navegador:<br><span style="word-break:break-all">{{.Link}}</span></p>
{{end}}<p style="font-size:13px;line-height:1.5;color:#555555;margin:24px 0 0">{{.Footer}}</p>
<p style="font-size:13px;color:#555555;margin:16px 0 0">— {{.Product}}</p>
</td></tr>
</table>
</td></tr>
</table>
</body>
</html>
`))
