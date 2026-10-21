// Package domain contém os tipos e regras puras da plataforma. Não faz I/O e
// não depende de outros pacotes internos (regra de lint "dominio-puro").
package domain

import (
	"errors"
	"fmt"
	"time"
)

// InstanceStatus é o estado de uma instância (um número de WhatsApp).
type InstanceStatus string

const (
	// StatusDisconnected: sem conexão ativa. Pode ter sessão salva (reconecta
	// sozinha) ou não (precisa parear).
	StatusDisconnected InstanceStatus = "DESCONECTADA"
	// StatusPairing: aguardando leitura do QR ou do código de pareamento.
	StatusPairing InstanceStatus = "PAREANDO"
	// StatusConnected: conectada e operando normalmente.
	StatusConnected InstanceStatus = "CONECTADA"
	// StatusDegraded: conectada, mas com restrição detectada (ex.: shadowban).
	// Envios ativos ficam pausados; a instância não é recriada.
	StatusDegraded InstanceStatus = "DEGRADADA"
	// StatusBanned: número banido. Estado final, salvo revisão manual.
	StatusBanned InstanceStatus = "BANIDA"
)

// InstanceEvent é o fato que provoca uma mudança de estado.
type InstanceEvent string

const (
	EventPairingStarted       InstanceEvent = "pareamento_iniciado"
	EventPairingFailed        InstanceEvent = "pareamento_falhou"   // QR/código expirou sem leitura, ou cancelado
	EventConnected            InstanceEvent = "conectada"           // conexão autenticada estabelecida
	EventDisconnected         InstanceEvent = "desconectada"        // queda de conexão; sessão continua válida
	EventSessionInvalidated   InstanceEvent = "sessao_invalidada"   // aparelho desvinculado; precisa parear de novo
	EventRestrictionDetected  InstanceEvent = "restricao_detectada" // ex.: shadowban
	EventRestrictionCleared   InstanceEvent = "restricao_encerrada" // envio normalizado
	EventBanned               InstanceEvent = "banida"
	EventBanLiftedAfterReview InstanceEvent = "banimento_revisado" // ação manual do admin da plataforma
)

// ErrInvalidTransition indica um evento que não se aplica ao estado atual.
var ErrInvalidTransition = errors.New("transição de estado inválida")

// Instance guarda o estado de ciclo de vida de uma instância.
type Instance struct {
	Status InstanceStatus
	// HasSession indica se existe sessão pareada salva (dá para reconectar
	// sem novo QR).
	HasSession bool
	// DegradedSince sobrevive a quedas de conexão: se a instância cair estando
	// degradada, volta degradada ao reconectar.
	DegradedSince *time.Time
	BannedAt      *time.Time
	ChangedAt     time.Time
}

// NewInstance cria uma instância recém-cadastrada, nunca pareada.
func NewInstance(at time.Time) Instance {
	return Instance{Status: StatusDisconnected, ChangedAt: at}
}

// Change descreve uma transição aplicada, para virar evento e auditoria.
type Change struct {
	From  InstanceStatus
	To    InstanceStatus
	Event InstanceEvent
	At    time.Time
}

// Apply aplica um evento e devolve o novo estado. Função pura: não altera a
// instância recebida. Eventos que não se aplicam ao estado atual devolvem
// ErrInvalidTransition e a instância original.
func Apply(inst Instance, ev InstanceEvent, at time.Time) (Instance, Change, error) {
	next := inst
	next.ChangedAt = at

	switch {
	case ev == EventPairingStarted && inst.Status == StatusDisconnected && !inst.HasSession:
		next.Status = StatusPairing

	case ev == EventPairingFailed && inst.Status == StatusPairing:
		next.Status = StatusDisconnected

	case ev == EventConnected && inst.Status == StatusPairing:
		next.Status = StatusConnected
		next.HasSession = true

	case ev == EventConnected && inst.Status == StatusDisconnected && inst.HasSession:
		next.Status = StatusConnected
		if inst.DegradedSince != nil {
			next.Status = StatusDegraded
		}

	case ev == EventDisconnected && (inst.Status == StatusConnected || inst.Status == StatusDegraded):
		next.Status = StatusDisconnected

	case ev == EventSessionInvalidated && inst.Status != StatusBanned && inst.HasSession:
		next.Status = StatusDisconnected
		next.HasSession = false

	case ev == EventRestrictionDetected && inst.Status == StatusConnected:
		next.Status = StatusDegraded
		t := at
		next.DegradedSince = &t

	case ev == EventRestrictionCleared && inst.Status == StatusDegraded:
		next.Status = StatusConnected
		next.DegradedSince = nil

	case ev == EventBanned && inst.Status != StatusBanned:
		next.Status = StatusBanned
		next.HasSession = false
		t := at
		next.BannedAt = &t

	case ev == EventBanLiftedAfterReview && inst.Status == StatusBanned:
		next.Status = StatusDisconnected
		next.BannedAt = nil
		next.DegradedSince = nil

	default:
		return inst, Change{}, fmt.Errorf("%w: evento %q no estado %q (sessão salva: %t)",
			ErrInvalidTransition, ev, inst.Status, inst.HasSession)
	}

	return next, Change{From: inst.Status, To: next.Status, Event: ev, At: at}, nil
}

// CanSend informa se a instância pode enviar mensagens ativas agora.
func (i Instance) CanSend() bool { return i.Status == StatusConnected }
