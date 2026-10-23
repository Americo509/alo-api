package tenant_test

import (
	"testing"

	"github.com/google/uuid"

	"github.com/Americo509/alo-api/internal/tenant"
	"github.com/Americo509/alo-api/internal/tenant/storetest"
)

func TestMemoryStoreContract(t *testing.T) {
	storetest.Run(t, func(*testing.T) (tenant.Store, func() uuid.UUID) {
		return tenant.NewMemory(), uuid.New
	})
}

func TestInviteMemoryContract(t *testing.T) {
	storetest.RunInvites(t, func(*testing.T) (tenant.Store, tenant.InviteStore, func(string) uuid.UUID) {
		mem := tenant.NewMemory()
		return mem, tenant.NewInviteMemory(mem), func(string) uuid.UUID { return uuid.New() }
	})
}
