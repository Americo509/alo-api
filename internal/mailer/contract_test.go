package mailer

import (
	"github.com/Americo509/alo-api/internal/identity/authflow"
	"github.com/Americo509/alo-api/internal/tenant"
)

// O OutboxMailer é o Mailer que o fluxo de autenticação e os convites esperam.
// Se uma interface mudar, este arquivo deixa de compilar.
var (
	_ authflow.Mailer = (*OutboxMailer)(nil)
	_ tenant.Mailer   = (*OutboxMailer)(nil)
)
