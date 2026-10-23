package bff

import (
	"github.com/Americo509/alo-api/internal/audit"
	"github.com/Americo509/alo-api/internal/identity"
	"github.com/Americo509/alo-api/internal/identity/authflow"
	"github.com/Americo509/alo-api/internal/identity/loginguard"
	"github.com/Americo509/alo-api/internal/identity/mfa"
	"github.com/Americo509/alo-api/internal/identity/oidclogin"
	"github.com/Americo509/alo-api/internal/identity/passkey"
	"github.com/Americo509/alo-api/internal/identity/session"
)

// Os testes usam dublês; estas linhas garantem que os serviços REAIS satisfazem
// as interfaces que as rotas esperam. Se uma assinatura mudar, o pacote deixa
// de compilar aqui, e não só em produção.
var (
	_ AuthFlow   = (*authflow.Service)(nil)
	_ Sessions   = (*session.Manager)(nil)
	_ Users      = (*identity.Repo)(nil)
	_ MFA        = (*mfa.Service)(nil)
	_ Passkeys   = (*passkey.Service)(nil)
	_ OIDC       = (*oidclogin.Service)(nil)
	_ LoginGuard = (*loginguard.Guard)(nil)
	_ Counter    = (*loginguard.MemoryCounter)(nil)
	_ Counter    = (*loginguard.RedisCounter)(nil)

	_ audit.Recorder = (*audit.PG)(nil)
	_ Challenger     = (*SiteVerify)(nil)
)
