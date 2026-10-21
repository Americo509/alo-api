// Package lease garante que cada instância tenha no máximo um worker dono
// (ADR-0005). O lease vive no Redis com TTL; cada aquisição recebe um fencing
// token monotônico. A garantia final contra dois donos simultâneos fica no
// Postgres, que recusa escrita com token velho (ADR-0010).
package lease

import (
	"context"
	"errors"
	"fmt"
	"time"
)

var (
	// ErrHeld: outro worker é dono da instância.
	ErrHeld = errors.New("lease: instância já tem dono")
	// ErrLost: o lease expirou ou foi tomado; o worker deve desconectar já.
	ErrLost = errors.New("lease: posse da instância perdida")
)

// Fence identifica uma posse. Token cresce a cada aquisição da mesma instância.
type Fence struct {
	InstanceID string
	Owner      string
	Token      int64
	AcquiredAt time.Time
}

// Backend é o armazenamento do lease. Implementações: Redis (produção) e
// memória (testes).
type Backend interface {
	// TryAcquire grava o dono se não houver outro e devolve o novo token.
	// ok=false quando já existe dono.
	TryAcquire(ctx context.Context, instanceID, owner string, ttl time.Duration) (token int64, ok bool, err error)
	// Renew estende o TTL só se owner ainda for o dono. ok=false se não for.
	Renew(ctx context.Context, instanceID, owner string, ttl time.Duration) (ok bool, err error)
	// Release remove o lease só se owner ainda for o dono.
	Release(ctx context.Context, instanceID, owner string) error
}

// Config define os tempos do lease. Ver Validate para as relações exigidas.
type Config struct {
	// TTL do lease no Redis.
	TTL time.Duration
	// RenewEvery: intervalo entre renovações. Recomendado TTL/3.
	RenewEvery time.Duration
	// GiveUpAfter: sem renovação bem-sucedida por esse tempo, o dono
	// considera a posse perdida e desconecta. Tem de ser menor que TTL, para
	// sobrar folga antes de outro worker conseguir adquirir. Recomendado TTL/2.
	GiveUpAfter time.Duration
	// SafetyDelay: espera depois de adquirir e antes de conectar, cobrindo a
	// desconexão de um dono anterior que ainda não percebeu a perda.
	SafetyDelay time.Duration
}

// DefaultConfig devolve valores iniciais conservadores, a calibrar com métricas.
func DefaultConfig() Config {
	return Config{
		TTL:         30 * time.Second,
		RenewEvery:  10 * time.Second,
		GiveUpAfter: 15 * time.Second,
		SafetyDelay: 20 * time.Second,
	}
}

// Validate checa as relações entre os tempos.
func (c Config) Validate() error {
	switch {
	case c.TTL <= 0 || c.RenewEvery <= 0 || c.GiveUpAfter <= 0 || c.SafetyDelay < 0:
		return errors.New("lease: tempos devem ser positivos")
	case c.RenewEvery >= c.GiveUpAfter:
		return fmt.Errorf("lease: RenewEvery (%s) deve ser menor que GiveUpAfter (%s)", c.RenewEvery, c.GiveUpAfter)
	case c.GiveUpAfter >= c.TTL:
		// O dono antigo precisa desistir (e desconectar) antes de o lease
		// expirar e outro worker conseguir adquirir.
		return fmt.Errorf("lease: GiveUpAfter (%s) deve ser menor que TTL (%s)", c.GiveUpAfter, c.TTL)
	}
	return nil
}
