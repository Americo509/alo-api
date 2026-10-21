//go:build integration

package lease

import (
	"context"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func startRedis(t *testing.T) *redis.Client {
	t.Helper()
	ctx := context.Background()
	c, err := testcontainers.Run(ctx, "redis:7.4.11-alpine",
		testcontainers.WithExposedPorts("6379/tcp"),
		testcontainers.WithWaitStrategy(wait.ForLog("Ready to accept connections").WithStartupTimeout(60*time.Second)),
	)
	testcontainers.CleanupContainer(t, c)
	if err != nil {
		t.Fatalf("subir redis: %v", err)
	}
	ep, err := c.Endpoint(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	rdb := redis.NewClient(&redis.Options{Addr: ep})
	t.Cleanup(func() { _ = rdb.Close() })
	return rdb
}

func TestIntegrationRedisBackend(t *testing.T) {
	rdb := startRedis(t)
	be := NewRedisBackend(rdb, "zgw:test")
	ctx := context.Background()
	ttl := 400 * time.Millisecond

	tok1, ok, err := be.TryAcquire(ctx, "inst-1", "worker-a", ttl)
	if err != nil || !ok || tok1 != 1 {
		t.Fatalf("primeira aquisição: tok=%d ok=%t err=%v", tok1, ok, err)
	}
	if _, ok, _ := be.TryAcquire(ctx, "inst-1", "worker-b", ttl); ok {
		t.Fatal("segundo dono adquiriu lease ocupado")
	}
	if ok, err := be.Renew(ctx, "inst-1", "worker-b", ttl); ok || err != nil {
		t.Fatalf("não-dono renovou: ok=%t err=%v", ok, err)
	}
	if ok, err := be.Renew(ctx, "inst-1", "worker-a", ttl); !ok || err != nil {
		t.Fatalf("dono não renovou: ok=%t err=%v", ok, err)
	}

	// Espera real curta: aqui o que se testa é o TTL do próprio Redis.
	deadline := time.Now().Add(5 * time.Second) //nolint:forbidigo // TTL real do Redis
	var tok2 int64
	for time.Now().Before(deadline) { //nolint:forbidigo // TTL real do Redis
		if tok2, ok, err = be.TryAcquire(ctx, "inst-1", "worker-b", ttl); ok || err != nil {
			break
		}
		time.Sleep(50 * time.Millisecond) //nolint:forbidigo // polling do TTL real do Redis
	}
	if err != nil || !ok {
		t.Fatalf("lease não expirou no Redis: ok=%t err=%v", ok, err)
	}
	if tok2 <= tok1 {
		t.Fatalf("fencing token não cresceu: %d -> %d", tok1, tok2)
	}
	if ok, _ := be.Renew(ctx, "inst-1", "worker-a", ttl); ok {
		t.Fatal("dono antigo renovou lease tomado")
	}
	if err := be.Release(ctx, "inst-1", "worker-a"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := be.TryAcquire(ctx, "inst-1", "worker-c", ttl); ok {
		t.Fatal("release do dono antigo liberou o lease do novo dono")
	}
	if err := be.Release(ctx, "inst-1", "worker-b"); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := be.TryAcquire(ctx, "inst-1", "worker-c", ttl); !ok || err != nil {
		t.Fatalf("release do dono atual não liberou: ok=%t err=%v", ok, err)
	}
}
