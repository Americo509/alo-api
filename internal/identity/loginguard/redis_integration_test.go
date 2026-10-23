//go:build integration

package loginguard

import (
	"context"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/Americo509/alo-api/internal/clock"
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

func TestIntegrationRedisCounter(t *testing.T) {
	rdb := startRedis(t)
	cnt := NewRedisCounter(rdb, "zgw:test")
	ctx := context.Background()

	if n, err := cnt.Get(ctx, "x"); err != nil || n != 0 {
		t.Fatalf("Get inicial = %d, %v", n, err)
	}
	for i := int64(1); i <= 3; i++ {
		n, err := cnt.Incr(ctx, "x", time.Minute)
		if err != nil || n != i {
			t.Fatalf("Incr %d = %d, %v", i, n, err)
		}
	}
	if n, _ := cnt.Get(ctx, "x"); n != 3 {
		t.Fatalf("Get após 3 incrementos = %d", n)
	}
	if err := cnt.Reset(ctx, "x"); err != nil {
		t.Fatal(err)
	}
	if n, _ := cnt.Get(ctx, "x"); n != 0 {
		t.Fatalf("Get após Reset = %d", n)
	}
}

func TestIntegrationRedisExpiry(t *testing.T) {
	rdb := startRedis(t)
	cnt := NewRedisCounter(rdb, "zgw:exp")
	ctx := context.Background()
	if _, err := cnt.Incr(ctx, "y", 200*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	ttl, err := rdb.PTTL(ctx, "zgw:exp:y").Result()
	if err != nil || ttl <= 0 || ttl > 300*time.Millisecond {
		t.Fatalf("TTL fora do esperado: %v (%v)", ttl, err)
	}
}

// O guard funciona ponta a ponta com o contador no Redis.
func TestIntegrationGuardWithRedis(t *testing.T) {
	rdb := startRedis(t)
	g, err := New(NewRedisCounter(rdb, "zgw:guard"), cfg, clock.Real())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for range 5 {
		if err := g.Fail(ctx, "1.2.3.4", "conta"); err != nil {
			t.Fatal(err)
		}
	}
	d, err := g.Check(ctx, "1.2.3.4", "conta")
	if err != nil {
		t.Fatal(err)
	}
	if !d.Challenge || d.Delay == 0 {
		t.Fatalf("esperava desafio e atraso após 5 falhas: %+v", d)
	}
	if err := g.Success(ctx, "1.2.3.4", "conta"); err != nil {
		t.Fatal(err)
	}
	if d, _ := g.Check(ctx, "9.9.9.9", "conta"); d.Challenge || d.Delay != 0 {
		t.Fatalf("Success não limpou no Redis: %+v", d)
	}
}
