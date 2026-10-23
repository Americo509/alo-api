// Package authz é a matriz de permissões por papel dentro de um tenant
// (ADR-0007, Q16). É pura: sem I/O, fácil de testar exaustivamente. Todo
// ponto de entrada autoriza por aqui, nunca comparando papéis à mão.
package authz

import "github.com/Americo509/alo-api/internal/identity"

// Permission é uma ação protegida.
type Permission string

const (
	TenantRead      Permission = "tenant:read"
	TenantUpdate    Permission = "tenant:update"
	MembersRead     Permission = "members:read"
	MembersManage   Permission = "members:manage"
	APIKeysManage   Permission = "apikeys:manage"
	InstancesManage Permission = "instances:manage"
	MessagesSend    Permission = "messages:send"
	ChatsRead       Permission = "chats:read"
	BillingManage   Permission = "billing:manage"
)

// minimum é o papel mínimo para cada permissão. Permissão ausente aqui não é
// concedida a ninguém (negar por padrão).
var minimum = map[Permission]identity.Role{
	TenantRead:      identity.RoleReader,
	MembersRead:     identity.RoleReader,
	ChatsRead:       identity.RoleReader,
	MessagesSend:    identity.RoleOperator,
	TenantUpdate:    identity.RoleAdmin,
	MembersManage:   identity.RoleAdmin,
	APIKeysManage:   identity.RoleAdmin,
	InstancesManage: identity.RoleAdmin,
	BillingManage:   identity.RoleOwner,
}

// Can informa se o papel tem a permissão.
func Can(role identity.Role, p Permission) bool {
	min, ok := minimum[p]
	return ok && role.Valid() && role.AtLeast(min)
}

// CanAssign informa se actor pode mudar um membro de current para next
// (current vazio = convite novo). O dono pode tudo; o admin só mexe com quem
// está abaixo dele e só concede papéis abaixo do dele — assim ninguém se
// promove nem derruba quem tem mais poder.
func CanAssign(actor, current, next identity.Role) bool {
	if !Can(actor, MembersManage) || !next.Valid() || (current != "" && !current.Valid()) {
		return false
	}
	if actor == identity.RoleOwner {
		return true
	}
	below := func(r identity.Role) bool { return r == "" || (r.Valid() && !r.AtLeast(actor)) }
	return below(current) && below(next)
}
