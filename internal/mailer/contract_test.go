package mailer

import "github.com/Americo509/alo-api/internal/identity/authflow"

// O OutboxMailer é o Mailer que o fluxo de autenticação espera. Se a interface
// mudar, este arquivo deixa de compilar.
var _ authflow.Mailer = (*OutboxMailer)(nil)
