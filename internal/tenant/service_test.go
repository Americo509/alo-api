package tenant

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/Americo509/alo-api/internal/authz"
	"github.com/Americo509/alo-api/internal/clock"
	"github.com/Americo509/alo-api/internal/identity"
)

var ctx = context.Background()

type fakeUsers struct{ m map[uuid.UUID]identity.User }

func (f *fakeUsers) GetUser(_ context.Context, id uuid.UUID) (identity.User, error) {
	u, ok := f.m[id]
	if !ok {
		return identity.User{}, identity.ErrNotFound
	}
	return u, nil
}

type env struct {
	svc   *Service
	store *Memory
	users *fakeUsers
}

func newEnv(t *testing.T) *env {
	t.Helper()
	store := NewMemory()
	users := &fakeUsers{m: map[uuid.UUID]identity.User{}}
	svc := NewService(store, users, clock.NewFake(time.Unix(1_700_000_000, 0)), Options{MaxOwnedPerUser: 2})
	return &env{svc: svc, store: store, users: users}
}

func (e *env) user(t *testing.T, name string) uuid.UUID {
	t.Helper()
	u := identity.User{ID: uuid.New(), Email: name + "@example.com", EmailVerified: true, Status: identity.StatusActive}
	e.users.m[u.ID] = u
	e.store.Profiles[u.ID] = u
	return u.ID
}

// tenantWith cria um tenant e adiciona membros com os papéis dados.
func (e *env) tenantWith(t *testing.T, owner uuid.UUID, others map[uuid.UUID]identity.Role) uuid.UUID {
	t.Helper()
	tn, err := e.svc.Create(ctx, owner, "Clínica Aurora")
	if err != nil {
		t.Fatal(err)
	}
	for u, r := range others {
		if err := e.svc.AddMember(ctx, owner, tn.ID, u, r); err != nil {
			t.Fatalf("add %s: %v", r, err)
		}
	}
	return tn.ID
}

func TestCreateMakesCreatorOwner(t *testing.T) {
	e := newEnv(t)
	u := e.user(t, "ana")
	tn, err := e.svc.Create(ctx, u, "  Clínica   Aurora ")
	if err != nil {
		t.Fatal(err)
	}
	if tn.Name != "Clínica Aurora" || tn.Status != StatusActive {
		t.Errorf("tenant: %+v", tn)
	}
	m, err := e.store.Member(ctx, tn.ID, u)
	if err != nil || m.Role != identity.RoleOwner {
		t.Fatalf("o criador deveria ser dono: %+v %v", m, err)
	}
	ms, _ := e.svc.List(ctx, u)
	if len(ms) != 1 || ms[0].Role != identity.RoleOwner {
		t.Errorf("lista: %+v", ms)
	}
}

func TestCreateRules(t *testing.T) {
	e := newEnv(t)
	u := e.user(t, "ana")
	for _, bad := range []string{"", "   ", strings.Repeat("a", 101), "nome\x00nulo", "linha" + string(rune(0x202e)) + "bidi"} {
		if _, err := e.svc.Create(ctx, u, bad); !errors.Is(err, ErrInvalidName) {
			t.Errorf("nome %q: %v", bad, err)
		}
	}
	unverified := e.user(t, "bia")
	usr := e.users.m[unverified]
	usr.EmailVerified = false
	e.users.m[unverified] = usr
	if _, err := e.svc.Create(ctx, unverified, "X"); !errors.Is(err, ErrEmailUnverified) {
		t.Errorf("e-mail não verificado: %v", err)
	}
	susp := e.user(t, "caio")
	usr = e.users.m[susp]
	usr.Status = identity.StatusSuspended
	e.users.m[susp] = usr
	if _, err := e.svc.Create(ctx, susp, "X"); !errors.Is(err, ErrUserNotActive) {
		t.Errorf("usuário suspenso: %v", err)
	}
	// Limite de 2 tenants por usuário.
	for i := 0; i < 2; i++ {
		if _, err := e.svc.Create(ctx, u, "T"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.svc.Create(ctx, u, "T"); !errors.Is(err, ErrLimitReached) {
		t.Errorf("limite: %v", err)
	}
}

func TestAuthorize(t *testing.T) {
	e := newEnv(t)
	owner, adm, op, rd, stranger := e.user(t, "o"), e.user(t, "a"), e.user(t, "p"), e.user(t, "l"), e.user(t, "x")
	tid := e.tenantWith(t, owner, map[uuid.UUID]identity.Role{adm: identity.RoleAdmin, op: identity.RoleOperator, rd: identity.RoleReader})

	cases := []struct {
		who  uuid.UUID
		perm authz.Permission
		want error
	}{
		{owner, authz.BillingManage, nil},
		{adm, authz.BillingManage, ErrForbidden},
		{adm, authz.APIKeysManage, nil},
		{op, authz.MessagesSend, nil},
		{op, authz.APIKeysManage, ErrForbidden},
		{rd, authz.ChatsRead, nil},
		{rd, authz.MessagesSend, ErrForbidden},
		{stranger, authz.TenantRead, ErrNotFound}, // não revela que o tenant existe
	}
	for i, c := range cases {
		if _, err := e.svc.Authorize(ctx, c.who, tid, c.perm); !errors.Is(err, c.want) {
			t.Errorf("caso %d (%s): %v, esperado %v", i, c.perm, err, c.want)
		}
	}
	if _, err := e.svc.Authorize(ctx, uuid.New(), tid, authz.TenantRead); !errors.Is(err, ErrForbidden) {
		t.Errorf("usuário inexistente: %v", err)
	}
}

func TestAuthorizeBlocksSuspendedUserAndTenant(t *testing.T) {
	e := newEnv(t)
	owner := e.user(t, "o")
	tid := e.tenantWith(t, owner, nil)

	usr := e.users.m[owner]
	usr.Status = identity.StatusSuspended
	e.users.m[owner] = usr
	if _, err := e.svc.Authorize(ctx, owner, tid, authz.TenantRead); !errors.Is(err, ErrForbidden) {
		t.Errorf("usuário suspenso passou: %v", err)
	}
	usr.Status = identity.StatusActive
	e.users.m[owner] = usr

	if err := e.svc.Suspend(ctx, tid); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Authorize(ctx, owner, tid, authz.TenantRead); !errors.Is(err, ErrSuspended) {
		t.Errorf("tenant suspenso passou: %v", err)
	}
	if err := e.svc.Reactivate(ctx, tid); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Authorize(ctx, owner, tid, authz.TenantRead); err != nil {
		t.Errorf("tenant reativado: %v", err)
	}
}

func TestRoleChangesFollowHierarchy(t *testing.T) {
	e := newEnv(t)
	owner, adm, op, rd := e.user(t, "o"), e.user(t, "a"), e.user(t, "p"), e.user(t, "l")
	tid := e.tenantWith(t, owner, map[uuid.UUID]identity.Role{adm: identity.RoleAdmin, op: identity.RoleOperator, rd: identity.RoleReader})

	// Admin NÃO pode: promover a admin, rebaixar o dono, mexer em outro admin.
	if err := e.svc.ChangeRole(ctx, adm, tid, op, identity.RoleAdmin); !errors.Is(err, ErrForbidden) {
		t.Errorf("admin promovendo a admin: %v", err)
	}
	if err := e.svc.ChangeRole(ctx, adm, tid, owner, identity.RoleReader); !errors.Is(err, ErrForbidden) {
		t.Errorf("admin rebaixando dono: %v", err)
	}
	// Admin PODE mudar operador para leitura.
	if err := e.svc.ChangeRole(ctx, adm, tid, op, identity.RoleReader); err != nil {
		t.Errorf("admin rebaixando operador: %v", err)
	}
	// Operador não gerencia ninguém.
	if err := e.svc.ChangeRole(ctx, op, tid, rd, identity.RoleOperator); !errors.Is(err, ErrForbidden) {
		t.Errorf("operador gerenciando: %v", err)
	}
	// Ninguém muda o próprio papel.
	if err := e.svc.ChangeRole(ctx, owner, tid, owner, identity.RoleAdmin); !errors.Is(err, ErrSelfChange) {
		t.Errorf("auto-mudança: %v", err)
	}
	if err := e.svc.ChangeRole(ctx, owner, tid, rd, "root"); !errors.Is(err, ErrInvalidRole) {
		t.Errorf("papel inválido: %v", err)
	}
	// Dono promove admin a dono.
	if err := e.svc.ChangeRole(ctx, owner, tid, adm, identity.RoleOwner); err != nil {
		t.Errorf("dono promovendo: %v", err)
	}
}

func TestNeverZeroOwners(t *testing.T) {
	e := newEnv(t)
	owner, other := e.user(t, "o"), e.user(t, "p")
	tid := e.tenantWith(t, owner, map[uuid.UUID]identity.Role{other: identity.RoleOwner})

	// Dois donos: um pode sair.
	if err := e.svc.Leave(ctx, other, tid); err != nil {
		t.Fatalf("sair com 2 donos: %v", err)
	}
	// Dono único: não pode sair, nem ser removido, nem se rebaixar.
	if err := e.svc.Leave(ctx, owner, tid); !errors.Is(err, ErrLastOwner) {
		t.Errorf("último dono saiu: %v", err)
	}
	if err := e.svc.RemoveMember(ctx, owner, tid, owner); !errors.Is(err, ErrLastOwner) {
		t.Errorf("último dono se removeu: %v", err)
	}
}

func TestLastOwnerSurvivesConcurrentDemotions(t *testing.T) {
	e := newEnv(t)
	a, b := e.user(t, "a"), e.user(t, "b")
	tid := e.tenantWith(t, a, map[uuid.UUID]identity.Role{b: identity.RoleOwner})

	var wg sync.WaitGroup
	results := make(chan error, 2)
	wg.Add(2)
	go func() { defer wg.Done(); results <- e.svc.ChangeRole(ctx, a, tid, b, identity.RoleReader) }()
	go func() { defer wg.Done(); results <- e.svc.ChangeRole(ctx, b, tid, a, identity.RoleReader) }()
	wg.Wait()
	close(results)

	owners := 0
	ms, _ := e.store.Members(ctx, tid)
	for _, m := range ms {
		if m.Role == identity.RoleOwner {
			owners++
		}
	}
	if owners < 1 {
		t.Fatal("o tenant ficou sem dono")
	}
}

func TestRemoveMemberRules(t *testing.T) {
	e := newEnv(t)
	owner, adm, op := e.user(t, "o"), e.user(t, "a"), e.user(t, "p")
	tid := e.tenantWith(t, owner, map[uuid.UUID]identity.Role{adm: identity.RoleAdmin, op: identity.RoleOperator})

	if err := e.svc.RemoveMember(ctx, adm, tid, owner); !errors.Is(err, ErrForbidden) {
		t.Errorf("admin removendo dono: %v", err)
	}
	if err := e.svc.RemoveMember(ctx, op, tid, adm); !errors.Is(err, ErrForbidden) {
		t.Errorf("operador removendo admin: %v", err)
	}
	if err := e.svc.RemoveMember(ctx, adm, tid, op); err != nil {
		t.Errorf("admin removendo operador: %v", err)
	}
	// Removido perde o acesso na hora.
	if _, err := e.svc.Authorize(ctx, op, tid, authz.TenantRead); !errors.Is(err, ErrNotFound) {
		t.Errorf("removido ainda autorizado: %v", err)
	}
}

func TestAddMemberRules(t *testing.T) {
	e := newEnv(t)
	owner, adm, a, b := e.user(t, "o"), e.user(t, "a"), e.user(t, "x"), e.user(t, "y")
	tid := e.tenantWith(t, owner, map[uuid.UUID]identity.Role{adm: identity.RoleAdmin})

	if err := e.svc.AddMember(ctx, adm, tid, a, identity.RoleAdmin); !errors.Is(err, ErrForbidden) {
		t.Errorf("admin criando admin: %v", err)
	}
	if err := e.svc.AddMember(ctx, adm, tid, a, identity.RoleOperator); err != nil {
		t.Errorf("admin criando operador: %v", err)
	}
	if err := e.svc.AddMember(ctx, adm, tid, a, identity.RoleReader); !errors.Is(err, ErrAlreadyMember) {
		t.Errorf("duplicado: %v", err)
	}
	if err := e.svc.AddMember(ctx, owner, tid, uuid.New(), identity.RoleReader); !errors.Is(err, ErrUserNotActive) {
		t.Errorf("usuário inexistente: %v", err)
	}
	if err := e.svc.AddMember(ctx, owner, tid, b, "root"); !errors.Is(err, ErrInvalidRole) {
		t.Errorf("papel inválido: %v", err)
	}
}

func TestTenantsAreIsolated(t *testing.T) {
	e := newEnv(t)
	a, b := e.user(t, "a"), e.user(t, "b")
	ta, tb := e.tenantWith(t, a, nil), e.tenantWith(t, b, nil)

	if _, err := e.svc.Get(ctx, a, tb); !errors.Is(err, ErrNotFound) {
		t.Errorf("a leu o tenant de b: %v", err)
	}
	if _, err := e.svc.Members(ctx, a, tb); !errors.Is(err, ErrNotFound) {
		t.Errorf("a listou membros de b: %v", err)
	}
	if err := e.svc.Rename(ctx, a, tb, "invadido"); !errors.Is(err, ErrNotFound) {
		t.Errorf("a renomeou b: %v", err)
	}
	if err := e.svc.AddMember(ctx, a, tb, a, identity.RoleOwner); !errors.Is(err, ErrNotFound) {
		t.Errorf("a entrou em b: %v", err)
	}
	if err := e.svc.Rename(ctx, a, ta, "Novo   Nome"); err != nil {
		t.Fatal(err)
	}
	if got, _ := e.svc.Get(ctx, a, ta); got.Name != "Novo Nome" {
		t.Errorf("nome: %q", got.Name)
	}
	ms, _ := e.svc.List(ctx, a)
	if len(ms) != 1 || ms[0].Tenant.ID != ta {
		t.Errorf("a lista de a mostra tenants alheios: %+v", ms)
	}
}
