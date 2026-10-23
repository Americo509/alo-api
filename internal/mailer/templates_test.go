package mailer

import (
	"strings"
	"testing"
)

const tokenSecret = "tok_ABC-def_123456789"

func tpl(t *testing.T) Templates {
	t.Helper()
	tp, err := NewTemplates("Alô API", "https://app.alo.example.com", "suporte@alo.example.com")
	if err != nil {
		t.Fatal(err)
	}
	return tp
}

func TestLinksCarryTokenInFragmentOnly(t *testing.T) {
	tp := tpl(t)
	for name, render := range map[string]func(string) (Rendered, error){
		"verificação": tp.EmailVerification,
		"recuperação": tp.PasswordRecovery,
	} {
		r, err := render(tokenSecret)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(r.Subject, tokenSecret) {
			t.Errorf("%s: token no assunto", name)
		}
		for body, content := range map[string]string{"texto": r.Text, "html": r.HTML} {
			// O token só pode aparecer depois de '#token=' (fragmento).
			i := strings.Index(content, tokenSecret)
			if i < 0 {
				t.Errorf("%s/%s: link sem o token", name, body)
				continue
			}
			if !strings.Contains(content[:i], "#token=") {
				t.Errorf("%s/%s: token fora do fragmento", name, body)
			}
			before := content[:strings.LastIndex(content[:i], "#token=")]
			if strings.Contains(before[strings.LastIndex(before, "https://"):], "?") {
				t.Errorf("%s/%s: token na query string (vai para logs): %s", name, body, content)
			}
		}
		if !strings.HasPrefix(r.Text, "Confirme") && !strings.HasPrefix(r.Text, "Redefinir") {
			t.Errorf("%s: texto inesperado: %.40q", name, r.Text)
		}
	}
}

func TestLinkTargets(t *testing.T) {
	tp := tpl(t)
	v, _ := tp.EmailVerification(tokenSecret)
	if !strings.Contains(v.Text, "https://app.alo.example.com/auth/verify-email#token="+tokenSecret) {
		t.Errorf("link de verificação: %s", v.Text)
	}
	r, _ := tp.PasswordRecovery(tokenSecret)
	if !strings.Contains(r.Text, "https://app.alo.example.com/auth/reset-password#token="+tokenSecret) {
		t.Errorf("link de recuperação: %s", r.Text)
	}
}

func TestValidityIsStatedInTheEmail(t *testing.T) {
	tp := tpl(t)
	v, _ := tp.EmailVerification(tokenSecret)
	if !strings.Contains(v.Text, "24 horas") {
		t.Errorf("verificação não informa a validade: %s", v.Text)
	}
	r, _ := tp.PasswordRecovery(tokenSecret)
	if !strings.Contains(r.Text, "30 minutos") {
		t.Errorf("recuperação não informa a validade: %s", r.Text)
	}
}

func TestAccountExistsAndPasswordChangedHaveNoToken(t *testing.T) {
	tp := tpl(t)
	a, _ := tp.AccountExists()
	if !strings.Contains(a.Text, "https://app.alo.example.com/auth/login") || strings.Contains(a.Text, "#token") {
		t.Errorf("aviso de conta existente: %s", a.Text)
	}
	c, _ := tp.PasswordChanged()
	if strings.Contains(c.Text, "http") {
		t.Errorf("aviso de senha alterada não deveria ter link: %s", c.Text)
	}
	if !strings.Contains(c.Text, "suporte@alo.example.com") {
		t.Errorf("sem contato de suporte: %s", c.Text)
	}
}

func TestHTMLEscapesInjectedMarkup(t *testing.T) {
	tp, err := NewTemplates(`<script>alert(1)</script>`, "https://app.alo.example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	r, _ := tp.EmailVerification(`"><img src=x onerror=alert(1)>`)
	if strings.Contains(r.HTML, "<script>") || strings.Contains(r.HTML, "<img") {
		t.Errorf("HTML sem escape: %s", r.HTML)
	}
	if !strings.Contains(r.HTML, "&lt;script&gt;") {
		t.Errorf("nome do produto deveria aparecer escapado: %s", r.HTML)
	}
}

func TestSubjectsMentionProductAndAreSingleLine(t *testing.T) {
	tp := tpl(t)
	for _, f := range []func() (Rendered, error){tp.PasswordChanged, tp.AccountExists} {
		r, _ := f()
		if !strings.HasSuffix(r.Subject, "— Alô API") || hasControl(r.Subject) {
			t.Errorf("assunto: %q", r.Subject)
		}
	}
}

func TestNewTemplatesValidation(t *testing.T) {
	bad := map[string][3]string{
		"produto vazio":       {"", "https://a.example.com", ""},
		"produto com CRLF":    {"A\r\nB", "https://a.example.com", ""},
		"http remoto":         {"P", "http://a.example.com", ""},
		"com caminho":         {"P", "https://a.example.com/painel", ""},
		"com query":           {"P", "https://a.example.com?x=1", ""},
		"sem host":            {"P", "https://", ""},
		"suporte inválido":    {"P", "https://a.example.com", "isto-nao-e-email"},
		"suporte com injeção": {"P", "https://a.example.com", "a@b.com\r\nBcc: x@y.com"},
	}
	for name, a := range bad {
		if _, err := NewTemplates(a[0], a[1], a[2]); err == nil {
			t.Errorf("%s: aceito", name)
		}
	}
	for _, ok := range []string{"https://a.example.com", "https://a.example.com/", "http://localhost:5173", "http://127.0.0.1:3000"} {
		if _, err := NewTemplates("P", ok, ""); err != nil {
			t.Errorf("%s recusado: %v", ok, err)
		}
	}
}

func TestInvitationEmail(t *testing.T) {
	tp := tpl(t)
	r, err := tp.Invitation(tokenSecret, "Clínica <b>Aurora</b>")
	if err != nil {
		t.Fatal(err)
	}
	for body, content := range map[string]string{"texto": r.Text, "html": r.HTML} {
		i := strings.Index(content, tokenSecret)
		if i < 0 || !strings.Contains(content[:i], "/auth/accept-invite#token=") {
			t.Errorf("%s: token fora do fragmento do link de convite", body)
		}
	}
	if strings.Contains(r.HTML, "<b>Aurora</b>") {
		t.Error("o nome do tenant não foi escapado no HTML")
	}
	if strings.Contains(r.Subject, tokenSecret) || strings.ContainsAny(r.Subject, "\r\n") {
		t.Errorf("assunto inválido: %q", r.Subject)
	}
	for _, bad := range []string{"", "  ", "linha\r\nBcc: x@y.z"} {
		if _, err := tp.Invitation(tokenSecret, bad); err == nil {
			t.Errorf("nome %q aceito", bad)
		}
	}
}
