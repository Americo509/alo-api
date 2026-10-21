package identity

import "testing"

func TestRoleAtLeast(t *testing.T) {
	cases := []struct {
		have, min Role
		want      bool
	}{
		{RoleOwner, RoleAdmin, true},
		{RoleAdmin, RoleAdmin, true},
		{RoleOperator, RoleAdmin, false},
		{RoleReader, RoleOperator, false},
		{RoleOwner, RoleReader, true},
	}
	for _, c := range cases {
		if got := c.have.AtLeast(c.min); got != c.want {
			t.Errorf("%s.AtLeast(%s) = %t, quer %t", c.have, c.min, got, c.want)
		}
	}
}

func TestRoleValid(t *testing.T) {
	for _, r := range []Role{RoleOwner, RoleAdmin, RoleOperator, RoleReader} {
		if !r.Valid() {
			t.Errorf("%s deveria ser válido", r)
		}
	}
	if Role("gerente").Valid() {
		t.Error("papel desconhecido passou como válido")
	}
}

func TestNormalizeEmail(t *testing.T) {
	ok := map[string]string{
		"  User@Example.COM ": "user@example.com",
		"a.b+tag@sub.dom.br":  "a.b+tag@sub.dom.br",
	}
	for in, want := range ok {
		got, err := NormalizeEmail(in)
		if err != nil || got != want {
			t.Errorf("NormalizeEmail(%q) = %q, %v; quer %q", in, got, err, want)
		}
	}
	bad := []string{"", "sem-arroba", "a@", "@b", "Nome <a@b.com>", "a@b c.com"}
	for _, in := range bad {
		if _, err := NormalizeEmail(in); err == nil {
			t.Errorf("NormalizeEmail(%q) deveria falhar", in)
		}
	}
}

func TestCanLogIn(t *testing.T) {
	if !(User{Status: StatusActive}).CanLogIn() {
		t.Error("ativo deveria poder logar")
	}
	for _, s := range []Status{StatusSuspended, StatusDisabled} {
		if (User{Status: s}).CanLogIn() {
			t.Errorf("%s não deveria poder logar", s)
		}
	}
}
