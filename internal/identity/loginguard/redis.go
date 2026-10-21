package loginguard

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisCounter implementa Counter no Redis. Incr usa INCR + EXPIRE para uma
// janela deslizante simples (o TTL é renovado a cada incremento).
type RedisCounter struct {
	rdb    redis.UniversalClient
	prefix string
}

// NewRedisCounter cria o contador.
func NewRedisCounter(rdb redis.UniversalClient, prefix string) *RedisCounter {
	return &RedisCounter{rdb: rdb, prefix: prefix}
}

func (c *RedisCounter) k(key string) string { return c.prefix + ":" + key }

// incrExpire: INCR e, no mesmo pipeline, renova o TTL.
var incrExpire = redis.NewScript(`
local n = redis.call("INCR", KEYS[1])
redis.call("PEXPIRE", KEYS[1], ARGV[1])
return n
`)

func (c *RedisCounter) Incr(ctx context.Context, key string, window time.Duration) (int64, error) {
	return incrExpire.Run(ctx, c.rdb, []string{c.k(key)}, window.Milliseconds()).Int64()
}

func (c *RedisCounter) Get(ctx context.Context, key string) (int64, error) {
	n, err := c.rdb.Get(ctx, c.k(key)).Int64()
	if errors.Is(err, redis.Nil) {
		return 0, nil
	}
	return n, err
}

func (c *RedisCounter) Reset(ctx context.Context, keys ...string) error {
	if len(keys) == 0 {
		return nil
	}
	full := make([]string, len(keys))
	for i, k := range keys {
		full[i] = c.k(k)
	}
	return c.rdb.Del(ctx, full...).Err()
}
