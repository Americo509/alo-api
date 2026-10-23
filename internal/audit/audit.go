// Package audit registra os eventos de segurança de autenticação (login,
// falhas, troca de senha, passkeys, vínculo de provedor...). Atende ao
// ADR-0007 (item 9): o registro de acesso exigido pelo Marco Civil (art. 15)
// e a transparência ao usuário ("atividade recente").
//
// Regras:
//   - o IP e o User-Agent ficam CIFRADOS em repouso (são dado pessoal);
//   - a tabela é append-only: o banco impede UPDATE;
//   - nunca se registra senha, token, código de MFA, cookie ou conteúdo de
//     mensagem; o Meta aceita só poucas chaves curtas e o chamador é
//     responsável por não passar segredos;
//   - retenção por prazo configurável, apagada por uma role dedicada.
package audit

import (
	"context"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

// Type identifica o evento.
type Type string

//nolint:gosec // G101: rótulos de tipos de evento (ex.: "senha_alterada"), não credenciais
const (
	Registered             Type = "cadastro"
	EmailVerified          Type = "email_verificado"
	LoginSuccess           Type = "login_ok"
	LoginFailure           Type = "login_falhou"
	LoginBlocked           Type = "login_bloqueado"
	MFASuccess             Type = "mfa_ok"
	MFAFailure             Type = "mfa_falhou"
	Logout                 Type = "logout"
	LogoutAll              Type = "logout_todas"
	SessionRevoked         Type = "sessao_encerrada"
	PasswordChanged        Type = "senha_alterada"
	PasswordResetRequested Type = "recuperacao_pedida"
	PasswordResetCompleted Type = "recuperacao_concluida"
	Reauthenticated        Type = "reautenticacao"
	TOTPEnabled            Type = "totp_ativado"
	TOTPDisabled           Type = "totp_desativado"
	RecoveryCodesCreated   Type = "codigos_recuperacao_gerados"
	RecoveryCodeUsed       Type = "codigo_recuperacao_usado"
	PasskeyAdded           Type = "passkey_adicionada"
	PasskeyRemoved         Type = "passkey_removida"
	PasskeyLogin           Type = "passkey_login"
	PasskeyCloneSuspected  Type = "passkey_clone_suspeito"
	OIDCLogin              Type = "oidc_login"
	OIDCAccountCreated     Type = "oidc_conta_criada"
	OIDCLinked             Type = "oidc_vinculado"
	OIDCFailure            Type = "oidc_falhou"
)

// Event é um evento de segurança.
type Event struct {
	Type      Type
	UserID    uuid.UUID // uuid.Nil se não houver usuário identificado (ex.: login com e-mail inexistente)
	IP        string
	UserAgent string
	Meta      map[string]string
	At        time.Time // preenchido pelo Recorder
}

// Recorder grava eventos. Falhar ao gravar NÃO deve derrubar a requisição de
// autenticação: quem chama registra o erro em log e segue.
type Recorder interface {
	Record(ctx context.Context, e Event) error
}

// Reader consulta e mantém o histórico.
type Reader interface {
	// RecentByUser devolve os eventos mais recentes do usuário (mais novo primeiro).
	RecentByUser(ctx context.Context, userID uuid.UUID, limit int) ([]Event, error)
	// DeleteOlderThan apaga eventos anteriores a cutoff (retenção).
	DeleteOlderThan(ctx context.Context, cutoff time.Time) (int64, error)
}

// Limites do Meta e dos campos de texto.
const (
	maxMetaEntries = 8
	maxMetaKey     = 30
	maxMetaValue   = 100
	maxUA          = 200
)

func clean(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == utf8.RuneError {
			return -1
		}
		return r
	}, s)
	if utf8.RuneCountInString(s) > max {
		s = string([]rune(s)[:max])
	}
	return s
}

// Sanitize limpa o evento: sem caracteres de controle, textos curtos e no
// máximo 8 entradas de Meta.
func Sanitize(e Event) Event {
	e.IP = clean(e.IP, 45)
	e.UserAgent = clean(e.UserAgent, maxUA)
	if len(e.Meta) > 0 {
		m := make(map[string]string, min(len(e.Meta), maxMetaEntries))
		for k, v := range e.Meta {
			if len(m) == maxMetaEntries {
				break
			}
			m[clean(k, maxMetaKey)] = clean(v, maxMetaValue)
		}
		e.Meta = m
	}
	return e
}

// Noop descarta os eventos (testes e componentes que não auditam).
type Noop struct{}

func (Noop) Record(context.Context, Event) error { return nil }
