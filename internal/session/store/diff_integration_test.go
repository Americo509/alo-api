//go:build integration

package store

// Teste diferencial (ADR-0010): a mesma sequência de operações roda no
// sqlstore original do whatsmeow (referência) e no nosso store; qualquer
// diferença de resultado falha. Um upgrade do whatsmeow que mude o
// comportamento esperado aparece aqui.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"go.mau.fi/whatsmeow/proto/waAdv"
	wastore "go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/store/sqlstore"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/util/keys"
)

type impl struct {
	name string
	st   wastore.AllSessionSpecificStores
	lids wastore.LIDStore
}

var (
	refOnce      sync.Once
	refContainer *sqlstore.Container
)

// pair cria uma instância de referência (sqlstore) e uma nossa.
func pair(t *testing.T) (ref, ours impl) {
	t.Helper()
	ctx := context.Background()
	refOnce.Do(func() {
		var err error
		refContainer, err = sqlstore.New(ctx, "pgx", db.OwnerDSN, nil)
		if err != nil {
			t.Fatalf("sqlstore: %v", err)
		}
	})
	jid := types.NewADJID(randDigits(13), 0, 1)
	dev := refContainer.NewDevice()
	dev.ID = &jid
	// O sqlstore exige a conta preenchida (colunas NOT NULL com tamanho fixo).
	dev.Account = &waAdv.ADVSignedDeviceIdentity{
		Details: []byte{1}, AccountSignature: make([]byte, 64),
		AccountSignatureKey: make([]byte, 32), DeviceSignature: make([]byte, 64),
	}
	if err := dev.Save(ctx); err != nil {
		t.Fatalf("salvar device de referência: %v", err)
	}
	f := newFixture(t)
	return impl{"sqlstore", dev.Identities.(wastore.AllSessionSpecificStores), dev.LIDs},
		impl{"nosso", f.s, f.s.LIDs()}
}

// randDigits gera números únicos por teste: o mapa LID do sqlstore é global
// ao banco de referência.
func randDigits(n int) string {
	var b strings.Builder
	for range n {
		d, _ := rand.Int(rand.Reader, big.NewInt(10))
		b.WriteString(d.String())
	}
	return b.String()
}

// same executa fn nas duas implementações e compara a saída normalizada.
func same(t *testing.T, ref, ours impl, step string, fn func(impl) []any) {
	t.Helper()
	a, b := norm(fn(ref)), norm(fn(ours))
	if a != b {
		t.Errorf("%s diverge\n  sqlstore: %s\n  nosso:    %s", step, a, b)
	}
}

// norm transforma resultados em texto comparável: erros viram "erro"/"ok"
// (as mensagens não precisam bater), tempos viram Unix, bytes viram hex.
func norm(vals []any) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = norm1(v)
	}
	return strings.Join(parts, " | ")
}

func norm1(v any) string {
	switch x := v.(type) {
	case nil:
		return "<nil>"
	case error:
		return "erro"
	case []byte:
		if x == nil {
			return "bytes(nil)"
		}
		return "0x" + hex.EncodeToString(x)
	case time.Time:
		if x.IsZero() {
			return "t(zero)"
		}
		return fmt.Sprintf("t(%d)", x.Unix())
	case map[string][]byte:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var b strings.Builder
		for _, k := range keys {
			fmt.Fprintf(&b, "%s=%s;", k, norm1(x[k]))
		}
		return "map{" + b.String() + "}"
	case types.ContactInfo:
		return fmt.Sprintf("contato{%t %q %q %q %q %q}", x.Found, x.FirstName, x.FullName, x.PushName, x.BusinessName, x.RedactedPhone)
	case types.LocalChatSettings:
		return fmt.Sprintf("cfg{%t %s %t %t}", x.Found, norm1(x.MutedUntil), x.Pinned, x.Archived)
	case *wastore.AppStateSyncKey:
		if x == nil {
			return "synckey(nil)"
		}
		return fmt.Sprintf("synckey{%s %s %d}", norm1(x.Data), norm1(x.Fingerprint), x.Timestamp)
	case *wastore.PrivacyToken:
		if x == nil {
			return "token(nil)"
		}
		return fmt.Sprintf("token{%s %s %s %s}", x.User, norm1(x.Token), norm1(x.Timestamp), norm1(x.SenderTimestamp))
	case *wastore.BufferedEvent:
		if x == nil {
			return "evento(nil)"
		}
		return fmt.Sprintf("evento{%s %s}", norm1(x.Plaintext), norm1(x.ServerTime)) // InsertTime depende do relógio
	default:
		return fmt.Sprintf("%v", x)
	}
}

func ok(err error) any { return err }

func key32(s string) (k [32]byte) {
	copy(k[:], s)
	return
}

func TestDiffIdentityAndSessions(t *testing.T) {
	ctx := context.Background()
	ref, ours := pair(t)
	u := randDigits(12)
	a0, a1, a2, other := u+":0", u+":1", u+":2", randDigits(12)+":0"
	missing := randDigits(12) + ":0"

	same(t, ref, ours, "identidade desconhecida é confiável", func(i impl) []any {
		r, err := i.st.IsTrustedIdentity(ctx, a0, key32("k1"))
		return []any{r, ok(err)}
	})
	same(t, ref, ours, "put/checar identidade", func(i impl) []any {
		e1 := i.st.PutIdentity(ctx, a0, key32("k1"))
		e2 := i.st.PutIdentity(ctx, a1, key32("k1"))
		r1, e3 := i.st.IsTrustedIdentity(ctx, a0, key32("k1"))
		r2, e4 := i.st.IsTrustedIdentity(ctx, a0, key32("k2"))
		e5 := i.st.PutIdentity(ctx, a0, key32("k2"))
		r3, e6 := i.st.IsTrustedIdentity(ctx, a0, key32("k2"))
		return []any{e1, e2, r1, e3, r2, e4, e5, r3, e6}
	})
	same(t, ref, ours, "apagar identidades", func(i impl) []any {
		e1 := i.st.DeleteIdentity(ctx, a0)
		r1, _ := i.st.IsTrustedIdentity(ctx, a0, key32("zz"))
		r2, _ := i.st.IsTrustedIdentity(ctx, a1, key32("zz"))
		e2 := i.st.DeleteAllIdentities(ctx, u)
		r3, _ := i.st.IsTrustedIdentity(ctx, a1, key32("zz"))
		return []any{e1, r1, r2, e2, r3}
	})
	same(t, ref, ours, "sessões", func(i impl) []any {
		g0, e0 := i.st.GetSession(ctx, a0)
		h0, _ := i.st.HasSession(ctx, a0)
		e1 := i.st.PutSession(ctx, a0, []byte("s0"))
		g1, _ := i.st.GetSession(ctx, a0)
		h1, _ := i.st.HasSession(ctx, a0)
		e2 := i.st.PutManySessions(ctx, map[string][]byte{a1: []byte("s1"), a2: []byte("s2"), other: []byte("so")})
		m, e3 := i.st.GetManySessions(ctx, []string{a0, a1, missing, a0})
		me, e4 := i.st.GetManySessions(ctx, nil)
		e5 := i.st.PutSession(ctx, a0, []byte("s0-novo"))
		g2, _ := i.st.GetSession(ctx, a0)
		return []any{g0, e0, h0, e1, g1, h1, e2, m, e3, me == nil, e4, e5, g2}
	})
	same(t, ref, ours, "apagar sessões", func(i impl) []any {
		e1 := i.st.DeleteSession(ctx, a1)
		h1, _ := i.st.HasSession(ctx, a1)
		h2, _ := i.st.HasSession(ctx, a2)
		e2 := i.st.DeleteAllSessions(ctx, u)
		h3, _ := i.st.HasSession(ctx, a2)
		h4, _ := i.st.HasSession(ctx, other)
		return []any{e1, h1, h2, e2, h3, h4}
	})
}

func TestDiffMigratePNToLID(t *testing.T) {
	ctx := context.Background()
	ref, ours := pair(t)
	pnUser, lidUser := randDigits(12), randDigits(14)
	pn := types.NewJID(pnUser, types.DefaultUserServer)
	lid := types.NewJID(lidUser, types.HiddenUserServer)
	group := randDigits(18) + "@g.us"

	same(t, ref, ours, "preparar dados do telefone", func(i impl) []any {
		return []any{
			i.st.PutSession(ctx, pnUser+":0", []byte("sess-pn-0")),
			i.st.PutSession(ctx, pnUser+":2", []byte("sess-pn-2")),
			i.st.PutSession(ctx, lidUser+":0", []byte("sess-lid-0-antiga")),
			i.st.PutIdentity(ctx, pnUser+":0", key32("id-pn")),
			i.st.PutSenderKey(ctx, group, pnUser+":2", []byte("sk-pn")),
		}
	})
	same(t, ref, ours, "migrar e conferir", func(i impl) []any {
		e1 := i.st.MigratePNToLID(ctx, pn, lid)
		m, _ := i.st.GetManySessions(ctx, []string{pnUser + ":0", pnUser + ":2", lidUser + ":0", lidUser + ":2"})
		t1, _ := i.st.IsTrustedIdentity(ctx, lidUser+":0", key32("id-pn"))
		t2, _ := i.st.IsTrustedIdentity(ctx, lidUser+":0", key32("outra"))
		skPN, _ := i.st.GetSenderKey(ctx, group, pnUser+":2")
		skLID, _ := i.st.GetSenderKey(ctx, group, lidUser+":2")
		// Segunda chamada é no-op (cache), mesmo com dado novo no telefone.
		_ = i.st.PutSession(ctx, pnUser+":5", []byte("depois"))
		e2 := i.st.MigratePNToLID(ctx, pn, lid)
		h, _ := i.st.HasSession(ctx, pnUser+":5")
		return []any{e1, m, t1, t2, skPN, skLID, e2, h}
	})
}

func TestDiffPreKeys(t *testing.T) {
	ctx := context.Background()
	ref, ours := pair(t)
	ids := func(ks []*keys.PreKey) string {
		var b strings.Builder
		for _, k := range ks {
			fmt.Fprintf(&b, "%d,", k.KeyID)
		}
		return b.String()
	}
	same(t, ref, ours, "pre-keys", func(i impl) []any {
		k5, e1 := i.st.GetOrGenPreKeys(ctx, 5)
		c0, _ := i.st.UploadedPreKeyCount(ctx)
		e2 := i.st.MarkPreKeysAsUploaded(ctx, 3)
		c1, _ := i.st.UploadedPreKeyCount(ctx)
		k4, e3 := i.st.GetOrGenPreKeys(ctx, 4)
		one, e4 := i.st.GenOnePreKey(ctx)
		c2, _ := i.st.UploadedPreKeyCount(ctx)
		g2, e5 := i.st.GetPreKey(ctx, 2)
		consistent := g2 != nil && *g2.Priv == *k5[1].Priv && *g2.Pub == *k5[1].Pub
		e6 := i.st.RemovePreKey(ctx, 2)
		g2b, _ := i.st.GetPreKey(ctx, 2)
		g999, e7 := i.st.GetPreKey(ctx, 999)
		return []any{ids(k5), e1, c0, e2, c1, ids(k4), e3, one.KeyID, e4, c2, e5, consistent, e6, g2b == nil, g999 == nil, e7}
	})
}

func TestDiffSenderKeysAndAppState(t *testing.T) {
	ctx := context.Background()
	ref, ours := pair(t)
	group, sender := randDigits(18)+"@g.us", randDigits(12)+":3"
	var h1, h2 [128]byte
	copy(h1[:], bytes.Repeat([]byte{1}, 128))
	copy(h2[:], bytes.Repeat([]byte{2}, 128))
	mac := func(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

	same(t, ref, ours, "sender keys", func(i impl) []any {
		g0, e0 := i.st.GetSenderKey(ctx, group, sender)
		e1 := i.st.PutSenderKey(ctx, group, sender, []byte("v1"))
		g1, _ := i.st.GetSenderKey(ctx, group, sender)
		e2 := i.st.PutSenderKey(ctx, group, sender, []byte("v2"))
		g2, _ := i.st.GetSenderKey(ctx, group, sender)
		return []any{g0, e0, e1, g1, e2, g2}
	})
	same(t, ref, ours, "app state sync keys", func(i impl) []any {
		l0, e0 := i.st.GetLatestAppStateSyncKeyID(ctx)
		e1 := i.st.PutAppStateSyncKey(ctx, []byte("id1"), wastore.AppStateSyncKey{Data: []byte("d1"), Fingerprint: []byte("f1"), Timestamp: 10})
		e2 := i.st.PutAppStateSyncKey(ctx, []byte("id2"), wastore.AppStateSyncKey{Data: []byte("d2"), Fingerprint: []byte("f2"), Timestamp: 20})
		e3 := i.st.PutAppStateSyncKey(ctx, []byte("id1"), wastore.AppStateSyncKey{Data: []byte("velho"), Fingerprint: []byte("fx"), Timestamp: 5})
		all, e4 := i.st.GetAllAppStateSyncKeys(ctx)
		allS := make([]string, len(all))
		for j, k := range all {
			allS[j] = norm1(k)
		}
		g1, _ := i.st.GetAppStateSyncKey(ctx, []byte("id1"))
		gm, _ := i.st.GetAppStateSyncKey(ctx, []byte("nao-existe"))
		l1, _ := i.st.GetLatestAppStateSyncKeyID(ctx)
		return []any{l0, e0, e1, e2, e3, strings.Join(allS, ","), e4, g1, gm, l1}
	})
	same(t, ref, ours, "app state version e MACs", func(i impl) []any {
		v0, hz, e0 := i.st.GetAppStateVersion(ctx, "regular")
		e1 := i.st.PutAppStateVersion(ctx, "regular", 3, h1)
		v1, hh, _ := i.st.GetAppStateVersion(ctx, "regular")
		e2 := i.st.PutAppStateMutationMACs(ctx, "regular", 3, []wastore.AppStateMutationMAC{{IndexMAC: mac(1), ValueMAC: mac(11)}, {IndexMAC: mac(2), ValueMAC: mac(12)}})
		e3 := i.st.PutAppStateMutationMACs(ctx, "regular", 4, []wastore.AppStateMutationMAC{{IndexMAC: mac(1), ValueMAC: mac(21)}})
		m1, _ := i.st.GetAppStateMutationMAC(ctx, "regular", mac(1))
		e4 := i.st.DeleteAppStateMutationMACs(ctx, "regular", [][]byte{mac(2)})
		m2, _ := i.st.GetAppStateMutationMAC(ctx, "regular", mac(2))
		e5 := i.st.PutAppStateVersion(ctx, "regular", 5, h2)
		v2, hh2, _ := i.st.GetAppStateVersion(ctx, "regular")
		e6 := i.st.DeleteAppStateVersion(ctx, "regular")
		m3, _ := i.st.GetAppStateMutationMAC(ctx, "regular", mac(1))
		e7 := i.st.PutAppStateVersion(ctx, "zerada", 0, h1)
		_, _, e8 := i.st.GetAppStateVersion(ctx, "zerada")
		return []any{v0, hz[:], e0, e1, v1, hh[:], e2, e3, m1, e4, m2, e5, v2, hh2[:], e6, m3, e7, e8}
	})
}

func TestDiffContactsAndChatSettings(t *testing.T) {
	ctx := context.Background()
	ref, ours := pair(t)
	c1 := types.NewJID(randDigits(12), types.DefaultUserServer)
	c2 := types.NewJID(randDigits(12), types.DefaultUserServer)
	chat := types.NewJID(randDigits(18), types.GroupServer)

	same(t, ref, ours, "contatos", func(i impl) []any {
		g0, e0 := i.st.GetContact(ctx, c1)
		ch1, prev1, e1 := i.st.PutPushName(ctx, c1, "Ana")
		ch2, prev2, _ := i.st.PutPushName(ctx, c1, "Ana")
		ch3, prev3, _ := i.st.PutPushName(ctx, c1, "Ana Maria")
		ch4, prev4, e2 := i.st.PutBusinessName(ctx, c1, "Clínica Ana")
		e3 := i.st.PutContactName(ctx, c1, "Ana", "Ana Maria Silva")
		g1, _ := i.st.GetContact(ctx, c1)
		e4 := i.st.PutAllContactNames(ctx, []wastore.ContactEntry{
			{JID: c2, FirstName: "Bia", FullName: "Bia Antiga"},
			{JID: c1, FirstName: "Ana", FullName: "Ana Atualizada"},
			{JID: c2, FirstName: "Bia", FullName: "Bia Nova"},
		})
		e5 := i.st.PutManyRedactedPhones(ctx, []wastore.RedactedPhoneEntry{{JID: c2, RedactedPhone: "+55 11 9****-0000"}})
		g2, _ := i.st.GetContact(ctx, c2)
		all, e6 := i.st.GetAllContacts(ctx)
		return []any{g0, e0, ch1, prev1, e1, ch2, prev2, ch3, prev3, ch4, prev4, e2, e3, g1, e4, e5, g2, all, e6}
	})
	same(t, ref, ours, "configurações de conversa", func(i impl) []any {
		s0, e0 := i.st.GetChatSettings(ctx, chat)
		w0, _ := i.st.GetWASARootSecretID(ctx, chat)
		e1 := i.st.PutMutedUntil(ctx, chat, time.Unix(1_900_000_000, 0))
		e2 := i.st.PutPinned(ctx, chat, true)
		s1, _ := i.st.GetChatSettings(ctx, chat)
		e3 := i.st.PutMutedUntil(ctx, chat, wastore.MutedForever)
		e4 := i.st.PutArchived(ctx, chat, true)
		s2, _ := i.st.GetChatSettings(ctx, chat)
		e5 := i.st.PutMutedUntil(ctx, chat, time.Time{})
		e6 := i.st.PutWASARootSecretID(ctx, chat, "ROOT1")
		s3, _ := i.st.GetChatSettings(ctx, chat)
		w1, _ := i.st.GetWASARootSecretID(ctx, chat)
		return []any{s0, e0, w0, e1, e2, s1, e3, e4, s2, e5, e6, s3, w1}
	})
}

func TestDiffLIDSecretsTokensSalt(t *testing.T) {
	ctx := context.Background()
	ref, ours := pair(t)
	pn := types.NewJID(randDigits(12), types.DefaultUserServer)
	lid := types.NewJID(randDigits(14), types.HiddenUserServer)
	lid2 := types.NewJID(randDigits(14), types.HiddenUserServer)
	unknownPN := types.NewJID(randDigits(12), types.DefaultUserServer)

	same(t, ref, ours, "mapa LID", func(i impl) []any {
		g0, e0 := i.lids.GetLIDForPN(ctx, pn)
		e1 := i.lids.PutLIDMapping(ctx, lid, pn)
		g1, _ := i.lids.GetLIDForPN(ctx, pn)
		p1, _ := i.lids.GetPNForLID(ctx, lid)
		pnDev := pn
		pnDev.Device = 2
		many, e2 := i.lids.GetManyLIDsForPNs(ctx, []types.JID{pnDev, unknownPN})
		e3 := i.lids.PutLIDMapping(ctx, pn, lid) // invertido: inválido
		_, e4 := i.lids.GetLIDForPN(ctx, lid)    // servidor errado
		return []any{g0, e0, e1, g1, p1, many, e2, e3 != nil, e4 != nil}
	})
	same(t, ref, ours, "segredos de mensagem com LID", func(i impl) []any {
		e1 := i.st.PutMessageSecret(ctx, pn, pn, "MSG1", []byte("seg1"))
		e2 := i.st.PutMessageSecret(ctx, pn, pn, "MSG1", []byte("ignorado"))
		s1, r1, e3 := i.st.GetMessageSecret(ctx, lid, lid, "MSG1")
		s2, r2, _ := i.st.GetMessageSecret(ctx, pn, pn, "MSG1")
		s3, r3, _ := i.st.GetMessageSecret(ctx, pn, pn, "OUTRA")
		e4 := i.st.PutMessageSecrets(ctx, []wastore.MessageSecretInsert{
			{Chat: pn, Sender: lid, ID: "MSG2", Secret: []byte("seg2")},
			{Chat: pn, Sender: lid, ID: "", Secret: []byte("sem id")},
			{Chat: types.EmptyJID, Sender: lid, ID: "MSG3", Secret: []byte("sem chat")},
		})
		s4, r4, _ := i.st.GetMessageSecret(ctx, lid, pn, "MSG2")
		s5, _, _ := i.st.GetMessageSecret(ctx, pn, lid, "MSG3")
		return []any{e1, e2, s1, r1, e3, s2, r2, s3, r3, e4, s4, r4, s5}
	})
	same(t, ref, ours, "privacy tokens", func(i impl) []any {
		g0, e0 := i.st.GetPrivacyToken(ctx, pn)
		e1 := i.st.PutPrivacyTokens(ctx, wastore.PrivacyToken{User: pn, Token: []byte("tk1"), Timestamp: time.Unix(100, 0), SenderTimestamp: time.Unix(50, 0)})
		g1, _ := i.st.GetPrivacyToken(ctx, lid)
		e2 := i.st.PutPrivacyTokens(ctx, wastore.PrivacyToken{User: pn, Token: []byte("velho"), Timestamp: time.Unix(90, 0)})
		g2, _ := i.st.GetPrivacyToken(ctx, pn)
		e3 := i.st.PutPrivacyTokens(ctx, wastore.PrivacyToken{User: pn, Token: []byte("tk2"), Timestamp: time.Unix(200, 0)})
		g3, _ := i.st.GetPrivacyToken(ctx, pn)
		n1, e4 := i.st.DeleteExpiredPrivacyTokens(ctx, time.Unix(150, 0))
		n2, _ := i.st.DeleteExpiredPrivacyTokens(ctx, time.Unix(250, 0))
		g4, _ := i.st.GetPrivacyToken(ctx, pn)
		return []any{g0, e0, e1, g1, e2, g2, e3, g3, n1, e4, n2, g4}
	})
	same(t, ref, ours, "remapear telefone para outro LID", func(i impl) []any {
		e1 := i.lids.PutLIDMapping(ctx, lid2, pn)
		g1, _ := i.lids.GetLIDForPN(ctx, pn)
		p1, _ := i.lids.GetPNForLID(ctx, lid)
		p2, _ := i.lids.GetPNForLID(ctx, lid2)
		return []any{e1, g1, p1, p2}
	})
	same(t, ref, ours, "salt NCT", func(i impl) []any {
		g0, e0 := i.st.GetNCTSalt(ctx)
		e1 := i.st.PutNCTSalt(ctx, []byte("sal1"))
		e2 := i.st.PutNCTSalt(ctx, []byte("sal2"))
		g1, _ := i.st.GetNCTSalt(ctx)
		e3 := i.st.DeleteNCTSalt(ctx)
		g2, _ := i.st.GetNCTSalt(ctx)
		return []any{g0, e0, e1, e2, g1, e3, g2}
	})
}

func TestDiffBuffers(t *testing.T) {
	ctx := context.Background()
	ref, ours := pair(t)
	chat := types.NewJID(randDigits(12), types.DefaultUserServer)
	alt := types.NewJID(randDigits(14), types.HiddenUserServer)
	var h1, h2 [32]byte
	copy(h1[:], "hash-um")
	copy(h2[:], "hash-dois")
	boom := errors.New("falha dentro da transação")

	same(t, ref, ours, "buffer de eventos", func(i impl) []any {
		g0, e0 := i.st.GetBufferedEvent(ctx, h1)
		e1 := i.st.PutBufferedEvent(ctx, h1, []byte("mensagem decifrada"), time.Unix(1_800_000_000, 0))
		g1, _ := i.st.GetBufferedEvent(ctx, h1)
		e2 := i.st.ClearBufferedEventPlaintext(ctx, h1)
		g2, _ := i.st.GetBufferedEvent(ctx, h1)
		e3 := i.st.PutBufferedEvent(ctx, h1, []byte("de novo"), time.Unix(1, 0)) // chave duplicada
		return []any{g0, e0, e1, g1, e2, g2, e3}
	})
	same(t, ref, ours, "transação de decifragem desfaz tudo em erro", func(i impl) []any {
		err := i.st.DoDecryptionTxn(ctx, func(ctx context.Context) error {
			if err := i.st.PutBufferedEvent(ctx, h2, []byte("x"), time.Unix(1, 0)); err != nil {
				return err
			}
			return boom
		})
		g, _ := i.st.GetBufferedEvent(ctx, h2)
		return []any{errors.Is(err, boom), g}
	})
	same(t, ref, ours, "buffer de reenvio", func(i impl) []any {
		_, _, e0 := i.st.GetOutgoingEvent(ctx, chat, alt, "M1")
		e1 := i.st.AddOutgoingEvent(ctx, chat, "M1", "fmt1", []byte("enviada"))
		f1, p1, e2 := i.st.GetOutgoingEvent(ctx, chat, types.EmptyJID, "M1")
		f2, p2, _ := i.st.GetOutgoingEvent(ctx, alt, chat, "M1")
		e3 := i.st.AddOutgoingEvent(ctx, chat, "M1", "fmt2", []byte("reescrita"))
		f3, p3, _ := i.st.GetOutgoingEvent(ctx, chat, alt, "M1")
		return []any{e0 != nil, e1, f1, p1, e2, f2, p2, e3, f3, p3}
	})
}

// Retenção usa o relógio injetado (o sqlstore usa time.Now; por isso fora do
// diferencial).
func TestBufferRetentionUsesClock(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)
	chat := types.NewJID(randDigits(12), types.DefaultUserServer)
	var h [32]byte
	copy(h[:], "retencao")
	must(t, f.s.PutBufferedEvent(ctx, h, []byte("x"), t0))
	must(t, f.s.AddOutgoingEvent(ctx, chat, "R1", "f", []byte("y")))

	f.clk.Advance(7*24*time.Hour + time.Minute)
	must(t, f.s.DeleteOldOutgoingEvents(ctx))
	must(t, f.s.DeleteOldBufferedHashes(ctx))
	if _, _, err := f.s.GetOutgoingEvent(ctx, chat, types.EmptyJID, "R1"); err == nil {
		t.Fatal("reenvio deveria expirar após 7 dias")
	}
	if g, _ := f.s.GetBufferedEvent(ctx, h); g == nil {
		t.Fatal("evento não deveria expirar antes de 14 dias")
	}
	f.clk.Advance(7 * 24 * time.Hour)
	must(t, f.s.DeleteOldBufferedHashes(ctx))
	if g, _ := f.s.GetBufferedEvent(ctx, h); g != nil {
		t.Fatal("evento deveria expirar após 14 dias")
	}
}
