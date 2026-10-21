package session

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisBackend implementa Backend no Redis.
type RedisBackend struct {
	rdb    redis.UniversalClient
	prefix string
}

// NewRedisBackend cria o backend. prefix separa ambientes (ex.: "zgw:prod").
func NewRedisBackend(rdb redis.UniversalClient, prefix string) *RedisBackend {
	return &RedisBackend{rdb: rdb, prefix: prefix}
}

func (b *RedisBackend) k(key string) string { return b.prefix + ":" + key }

func (b *RedisBackend) Set(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	return b.rdb.Set(ctx, b.k(key), value, ttl).Err()
}

func (b *RedisBackend) Get(ctx context.Context, key string) ([]byte, error) {
	v, err := b.rdb.Get(ctx, b.k(key)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, ErrNotFound
	}
	return v, err
}

func (b *RedisBackend) Del(ctx context.Context, keys ...string) error {
	if len(keys) == 0 {
		return nil
	}
	full := make([]string, len(keys))
	for i, k := range keys {
		full[i] = b.k(k)
	}
	return b.rdb.Del(ctx, full...).Err()
}

func (b *RedisBackend) Expire(ctx context.Context, key string, ttl time.Duration) error {
	return b.rdb.Expire(ctx, b.k(key), ttl).Err()
}

func (b *RedisBackend) SetAdd(ctx context.Context, set, member string, ttl time.Duration) error {
	// SADD + bump no TTL do conjunto; o índice nunca vive além da sessão mais longa.
	pipe := b.rdb.TxPipeline()
	pipe.SAdd(ctx, b.k(set), member)
	pipe.Expire(ctx, b.k(set), ttl)
	_, err := pipe.Exec(ctx)
	return err
}

func (b *RedisBackend) SetMembers(ctx context.Context, set string) ([]string, error) {
	return b.rdb.SMembers(ctx, b.k(set)).Result()
}

func (b *RedisBackend) SetRem(ctx context.Context, set, member string) error {
	return b.rdb.SRem(ctx, b.k(set), member).Err()
}
