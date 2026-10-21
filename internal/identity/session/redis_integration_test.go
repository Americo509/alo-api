//go:build integration

package session

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/zapgateway/zap-gateway/internal/clock"
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

// Com o Redis real, o relógio é o do sistema (o TTL é do próprio Redis), então
// os tempos aqui são curtos de verdade.
func TestIntegrationRedisSession(t *testing.T) {
	rdb := startRedis(t)
	clk := clock.Real()
	m, err := NewManager(NewRedisBackend(rdb, "zgw:test"), Config{Idle: time.Minute, Absolute: 5 * time.Minute}, clk)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	uid := uuid.New()

	id, _, err := m.Create(ctx, uid, "pwd")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Get(ctx, id); err != nil {
		t.Fatalf("Get: %v", err)
	}
	newID, _, err := m.Rotate(ctx, id, "mfa")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Get(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Fatal("ID antigo válido após rotação no Redis")
	}
	if err := m.RevokeAll(ctx, uid); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Get(ctx, newID); !errors.Is(err, ErrNotFound) {
		t.Fatal("sessão válida após RevokeAll no Redis")
	}
}

func TestIntegrationRedisTTLExpires(t *testing.T) {
	rdb := startRedis(t)
	m, err := NewManager(NewRedisBackend(rdb, "zgw:ttl"), Config{Idle: time.Minute, Absolute: time.Minute}, clock.Real())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	id, _, err := m.Create(ctx, uuid.New())
	if err != nil {
		t.Fatal(err)
	}
	// Confere que a chave tem TTL positivo (<= 1 min) definido no Redis.
	keys, err := rdb.Keys(ctx, "zgw:ttl:"+keyPrefix+"*").Result()
	if err != nil || len(keys) != 1 {
		t.Fatalf("chaves = %v (%v)", keys, err)
	}
	ttl, err := rdb.PTTL(ctx, keys[0]).Result()
	if err != nil || ttl <= 0 || ttl > time.Minute+time.Second {
		t.Fatalf("TTL fora do esperado: %v (%v)", ttl, err)
	}
	_ = id
}
