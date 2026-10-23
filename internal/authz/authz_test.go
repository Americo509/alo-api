package authz

import (
	"testing"

	"github.com/Americo509/alo-api/internal/identity"
)

const (
	o = identity.RoleOwner
	a = identity.RoleAdmin
	p = identity.RoleOperator
	l = identity.RoleReader
)

func TestMatrix(t *testing.T) {
	want := map[Permission][]identity.Role{
		TenantRead:      {l, p, a, o},
		MembersRead:     {l, p, a, o},
		ChatsRead:       {l, p, a, o},
		MessagesSend:    {p, a, o},
		TenantUpdate:    {a, o},
		MembersManage:   {a, o},
		APIKeysManage:   {a, o},
		InstancesManage: {a, o},
		BillingManage:   {o},
	}
	for perm, allowed := range want {
		for _, r := range []identity.Role{l, p, a, o} {
			expect := false
			for _, x := range allowed {
				expect = expect || x == r
			}
			if got := Can(r, perm); got != expect {
				t.Errorf("Can(%s,%s)=%t, esperado %t", r, perm, got, expect)
			}
		}
	}
}

func TestDenyByDefault(t *testing.T) {
	if Can(o, "inexistente:perm") {
		t.Error("permissão desconhecida concedida")
	}
	if Can("", TenantRead) || Can("root", TenantRead) {
		t.Error("papel inválido concedido")
	}
}

func TestCanAssign(t *testing.T) {
	cases := []struct {
		name                string
		actor, current, nxt identity.Role
		ok                  bool
	}{
		{"dono convida dono", o, "", o, true},
		{"dono rebaixa dono", o, o, p, true},
		{"admin convida operador", a, "", p, true},
		{"admin convida admin", a, "", a, false},
		{"admin convida dono", a, "", o, false},
		{"admin rebaixa dono", a, o, l, false},
		{"admin rebaixa outro admin", a, a, l, false},
		{"admin promove operador a admin", a, p, a, false},
		{"admin muda operador para leitura", a, p, l, true},
		{"operador não gerencia", p, "", l, false},
		{"leitura não gerencia", l, l, l, false},
		{"papel novo inválido", o, "", "root", false},
		{"papel atual inválido", o, "root", l, false},
	}
	for _, c := range cases {
		if got := CanAssign(c.actor, c.current, c.nxt); got != c.ok {
			t.Errorf("%s: %t", c.name, got)
		}
	}
}
