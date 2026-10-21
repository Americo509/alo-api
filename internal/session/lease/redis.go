package lease

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

// Scripts Lua: cada operação é atômica no Redis. Chaves usam hash tag
// {instanceID} para cair no mesmo slot em Redis Cluster.

// KEYS[1]=lease, KEYS[2]=fence, ARGV[1]=owner, ARGV[2]=ttl ms
var acquireScript = redis.NewScript(`
if redis.call("SET", KEYS[1], ARGV[1], "NX", "PX", ARGV[2]) then
  return redis.call("INCR", KEYS[2])
end
return false
`)

// KEYS[1]=lease, ARGV[1]=owner, ARGV[2]=ttl ms
var renewScript = redis.NewScript(`
if redis.call("GET", KEYS[1]) == ARGV[1] then
  return redis.call("PEXPIRE", KEYS[1], ARGV[2])
end
return 0
`)

// KEYS[1]=lease, ARGV[1]=owner
var releaseScript = redis.NewScript(`
if redis.call("GET", KEYS[1]) == ARGV[1] then
  return redis.call("DEL", KEYS[1])
end
return 0
`)

// RedisBackend implementa Backend no Redis.
type RedisBackend struct {
	rdb    redis.UniversalClient
	prefix string
}

// NewRedisBackend cria o backend. prefix separa ambientes (ex.: "zgw:prod").
func NewRedisBackend(rdb redis.UniversalClient, prefix string) *RedisBackend {
	return &RedisBackend{rdb: rdb, prefix: prefix}
}

func (r *RedisBackend) keys(instanceID string) (lease, fence string) {
	tag := "{" + instanceID + "}"
	return r.prefix + ":lease:" + tag, r.prefix + ":fence:" + tag
}

func (r *RedisBackend) TryAcquire(ctx context.Context, instanceID, owner string, ttl time.Duration) (int64, bool, error) {
	lk, fk := r.keys(instanceID)
	tok, err := acquireScript.Run(ctx, r.rdb, []string{lk, fk}, owner, ttl.Milliseconds()).Int64()
	if errors.Is(err, redis.Nil) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return tok, true, nil
}

func (r *RedisBackend) Renew(ctx context.Context, instanceID, owner string, ttl time.Duration) (bool, error) {
	lk, _ := r.keys(instanceID)
	n, err := renewScript.Run(ctx, r.rdb, []string{lk}, owner, ttl.Milliseconds()).Int64()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

func (r *RedisBackend) Release(ctx context.Context, instanceID, owner string) error {
	lk, _ := r.keys(instanceID)
	return releaseScript.Run(ctx, r.rdb, []string{lk}, owner).Err()
}
