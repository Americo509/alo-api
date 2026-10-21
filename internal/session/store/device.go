package store

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"go.mau.fi/whatsmeow/proto/waAdv"
	wastore "go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/util/keys"
	waLog "go.mau.fi/whatsmeow/util/log"
)

// Container implementa store.DeviceContainer para a instância do Store.
type Container struct {
	s *Store
}

var (
	_ wastore.DeviceContainer          = (*Container)(nil)
	_ wastore.AllSessionSpecificStores = (*Store)(nil)
)

// NewContainer cria o container da instância.
func NewContainer(s *Store) *Container { return &Container{s: s} }

// deviceRecord é tudo o que a Device precisa persistir. Vai inteiro num blob
// cifrado: chaves privadas, JID do número, conta e nomes.
type deviceRecord struct {
	JID                string `json:"jid"`
	LID                string `json:"lid,omitempty"`
	RegistrationID     uint32 `json:"rid"`
	NoisePriv          []byte `json:"noise"`
	IdentityPriv       []byte `json:"ident"`
	SignedPreKeyPriv   []byte `json:"spk"`
	SignedPreKeyID     uint32 `json:"spk_id"`
	SignedPreKeySig    []byte `json:"spk_sig"`
	AdvSecretKey       []byte `json:"adv"`
	AdvDetails         []byte `json:"adv_details"`
	AdvAccountSig      []byte `json:"adv_acc_sig"`
	AdvAccountSigKey   []byte `json:"adv_acc_sig_key"`
	AdvDeviceSig       []byte `json:"adv_dev_sig"`
	Platform           string `json:"platform,omitempty"`
	BusinessName       string `json:"business,omitempty"`
	PushName           string `json:"push,omitempty"`
	FacebookUUID       string `json:"fb_uuid,omitempty"`
	LIDMigrationTS     int64  `json:"lid_mig_ts,omitempty"`
	CompanionMetaNonce string `json:"cmn,omitempty"`
}

func (r *deviceRecord) wipe() {
	for _, b := range [][]byte{r.NoisePriv, r.IdentityPriv, r.SignedPreKeyPriv, r.AdvSecretKey} {
		clear(b)
	}
}

// Device carrega a device da instância ou, se ainda não pareou, devolve uma
// nova com chaves geradas (ainda não gravada; o pareamento chama Save).
func (c *Container) Device(ctx context.Context) (*wastore.Device, error) {
	var enc []byte
	err := c.s.read(ctx, func(ctx context.Context, tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT device_enc FROM wa.devices WHERE instance_id = $1`, c.s.instanceID).Scan(&enc)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return c.NewDevice()
	} else if err != nil {
		return nil, err
	}
	pt, err := c.s.open(enc, "devices")
	if err != nil {
		return nil, err
	}
	defer clear(pt)
	var r deviceRecord
	if err := json.Unmarshal(pt, &r); err != nil {
		return nil, fmt.Errorf("store: device corrompida: %w", err)
	}
	defer r.wipe()
	return c.decode(&r)
}

// NewDevice gera identidade nova. Diferente do sqlstore (math/rand), o
// registration ID vem de crypto/rand.
func (c *Container) NewDevice() (*wastore.Device, error) {
	var rid [4]byte
	if _, err := rand.Read(rid[:]); err != nil {
		return nil, err
	}
	adv := make([]byte, 32)
	if _, err := rand.Read(adv); err != nil {
		return nil, err
	}
	d := &wastore.Device{
		Log:            waLog.Noop,
		Container:      c,
		NoiseKey:       keys.NewKeyPair(),
		IdentityKey:    keys.NewKeyPair(),
		RegistrationID: binary.BigEndian.Uint32(rid[:]),
		AdvSecretKey:   adv,
	}
	d.SignedPreKey = d.IdentityKey.CreateSignedPreKey(1)
	return d, nil
}

func (c *Container) decode(r *deviceRecord) (*wastore.Device, error) {
	if len(r.NoisePriv) != 32 || len(r.IdentityPriv) != 32 || len(r.SignedPreKeyPriv) != 32 || len(r.SignedPreKeySig) != 64 {
		return nil, ErrInvalidLength
	}
	jid, err := types.ParseJID(r.JID)
	if err != nil {
		return nil, fmt.Errorf("store: JID da device inválido: %w", err)
	}
	d := &wastore.Device{
		Log:                   waLog.Noop,
		ID:                    &jid,
		RegistrationID:        r.RegistrationID,
		NoiseKey:              keys.NewKeyPairFromPrivateKey(*(*[32]byte)(r.NoisePriv)),
		IdentityKey:           keys.NewKeyPairFromPrivateKey(*(*[32]byte)(r.IdentityPriv)),
		AdvSecretKey:          append([]byte(nil), r.AdvSecretKey...),
		Platform:              r.Platform,
		BusinessName:          r.BusinessName,
		PushName:              r.PushName,
		LIDMigrationTimestamp: r.LIDMigrationTS,
		CompanionMetaNonce:    r.CompanionMetaNonce,
		Account: &waAdv.ADVSignedDeviceIdentity{
			Details:             r.AdvDetails,
			AccountSignature:    r.AdvAccountSig,
			AccountSignatureKey: r.AdvAccountSigKey,
			DeviceSignature:     r.AdvDeviceSig,
		},
	}
	if r.LID != "" {
		if d.LID, err = types.ParseJID(r.LID); err != nil {
			return nil, fmt.Errorf("store: LID da device inválido: %w", err)
		}
	}
	if r.FacebookUUID != "" {
		if d.FacebookUUID, err = uuid.Parse(r.FacebookUUID); err != nil {
			return nil, fmt.Errorf("store: facebook_uuid inválido: %w", err)
		}
	}
	sig := *(*[64]byte)(r.SignedPreKeySig)
	d.SignedPreKey = &keys.PreKey{
		KeyPair:   *keys.NewKeyPairFromPrivateKey(*(*[32]byte)(r.SignedPreKeyPriv)),
		KeyID:     r.SignedPreKeyID,
		Signature: &sig,
	}
	c.initialize(d)
	return d, nil
}

func (c *Container) initialize(d *wastore.Device) {
	d.SetAllStores(c.s)
	d.LIDs = c.s.lids
	d.Container = c
	d.Initialized = true
}

// PutDevice grava a device inteira, cifrada. Chamado pelo whatsmeow via
// Device.Save (por exemplo, ao concluir o pareamento).
func (c *Container) PutDevice(ctx context.Context, d *wastore.Device) error {
	if d.ID == nil {
		return ErrDeviceIDMustBeSet
	}
	r := deviceRecord{
		JID:                d.ID.String(),
		RegistrationID:     d.RegistrationID,
		NoisePriv:          d.NoiseKey.Priv[:],
		IdentityPriv:       d.IdentityKey.Priv[:],
		SignedPreKeyPriv:   d.SignedPreKey.Priv[:],
		SignedPreKeyID:     d.SignedPreKey.KeyID,
		AdvSecretKey:       d.AdvSecretKey,
		Platform:           d.Platform,
		BusinessName:       d.BusinessName,
		PushName:           d.PushName,
		LIDMigrationTS:     d.LIDMigrationTimestamp,
		CompanionMetaNonce: d.CompanionMetaNonce,
	}
	if d.SignedPreKey.Signature != nil {
		r.SignedPreKeySig = d.SignedPreKey.Signature[:]
	}
	if d.Account != nil {
		r.AdvDetails, r.AdvAccountSig = d.Account.Details, d.Account.AccountSignature
		r.AdvAccountSigKey, r.AdvDeviceSig = d.Account.AccountSignatureKey, d.Account.DeviceSignature
	}
	if !d.LID.IsEmpty() {
		r.LID = d.LID.String()
	}
	if d.FacebookUUID != uuid.Nil {
		r.FacebookUUID = d.FacebookUUID.String()
	}
	pt, err := json.Marshal(r)
	if err != nil {
		return err
	}
	enc, err := c.s.seal(pt, "devices")
	clear(pt)
	if err != nil {
		return err
	}
	err = c.s.write(ctx, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO wa.devices (instance_id, tenant_id, device_enc, updated_at) VALUES ($1, $2, $3, $4)
			ON CONFLICT (instance_id) DO UPDATE SET device_enc = excluded.device_enc, updated_at = excluded.updated_at`,
			c.s.instanceID, c.s.tenantID, enc, c.s.clock.Now())
		return err
	})
	if err != nil {
		return err
	}
	if !d.Initialized {
		c.initialize(d)
	}
	return nil
}

// sessionTables: tudo que pertence à sessão pareada. instance_keys e
// instance_owner ficam: a instância continua existindo e pode parear de novo.
var sessionTables = []string{
	"identity_keys", "sessions", "pre_keys", "sender_keys", "app_state_mutation_macs",
	"app_state_version", "app_state_sync_keys", "contacts", "chat_settings", "message_secrets",
	"privacy_tokens", "nct_salt", "lid_map", "event_buffer", "retry_buffer", "devices",
}

// DeleteDevice apaga todo o estado da sessão (logout ou desvínculo).
func (c *Container) DeleteDevice(ctx context.Context, d *wastore.Device) error {
	if d.ID == nil {
		return ErrDeviceIDMustBeSet
	}
	err := c.s.write(ctx, func(ctx context.Context, tx pgx.Tx) error {
		for _, t := range sessionTables {
			if _, err := tx.Exec(ctx, fmt.Sprintf(`DELETE FROM wa.%s WHERE instance_id = $1`, t), c.s.instanceID); err != nil {
				return fmt.Errorf("store: apagar %s: %w", t, err)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	c.s.contactMu.Lock()
	c.s.contactCache = map[string]*contactRecord{}
	c.s.contactMu.Unlock()
	c.s.lids.mu.Lock()
	c.s.lids.pnToLID, c.s.lids.lidToPN, c.s.lids.cacheFilled = map[string]string{}, map[string]string{}, false
	c.s.lids.mu.Unlock()
	return nil
}
