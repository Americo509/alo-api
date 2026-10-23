//go:build integration

package ephemeral

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
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

func TestIntegrationRedisTakeIsAtomic(t *testing.T) {
	rdb := startRedis(t)
	s := NewRedis(rdb, "zgw:test")
	ctx := context.Background()
	if err := s.Put(ctx, "k", []byte("v"), time.Minute); err != nil {
		t.Fatal(err)
	}
	var wins atomic.Int32
	var wg sync.WaitGroup
	for range 30 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.Take(ctx, "k"); err == nil {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("%d consumiram o mesmo valor no Redis, quer 1", wins.Load())
	}
	if _, err := s.Take(ctx, "k"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Take após consumo: %v", err)
	}
}
