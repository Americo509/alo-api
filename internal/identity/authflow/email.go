package authflow

import "context"

// Mailer envia os e-mails transacionais da autenticação. A implementação real
// (provedor + domínio) está em aberto na Q20; o serviço depende só desta porta,
// e o envio deve ser enfileirado (outbox) para não bloquear a requisição nem
// vazar, pelo tempo de resposta, se a conta existe.
type Mailer interface {
	// SendEmailVerification manda o link de verificação (token embutido).
	SendEmailVerification(ctx context.Context, to, token string) error
	// SendPasswordRecovery manda o link de recuperação (token embutido).
	SendPasswordRecovery(ctx context.Context, to, token string) error
	// SendPasswordChanged avisa que a senha foi alterada (sem token).
	SendPasswordChanged(ctx context.Context, to string) error
	// SendAccountExists avisa, em vez do link de verificação, que já existe
	// conta com aquele e-mail (resposta ao cadastro duplicado sem revelar isso
	// a quem fez a requisição).
	SendAccountExists(ctx context.Context, to string) error
}
