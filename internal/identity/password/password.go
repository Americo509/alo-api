// Package password cuida do armazenamento de senhas conforme o ADR-0007 e as
// recomendações do NIST SP 800-63B:
//
//   - hash Argon2id (OWASP: m=19 MiB, t=2, p=1 como piso), formato PHC;
//   - pepper aplicado com HMAC-SHA256 antes do Argon2id, com a chave no
//     KMS/Vault — vazou o banco, os hashes não são atacáveis offline;
//   - os parâmetros ficam gravados junto do hash, o que permite rehash
//     transparente quando forem elevados;
//   - comparação em tempo constante.
//
// O pacote NÃO decide política de tamanho/força da senha nem checagem de
// vazamento; isso fica na borda (pacote policy), porque depende de I/O.
package password

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// ErrMismatch indica senha incorreta (ou hash de outro formato).
var ErrMismatch = errors.New("password: senha não confere")

// Params são os parâmetros do Argon2id. Gravados no hash (formato PHC).
type Params struct {
	Memory      uint32 // KiB
	Time        uint32 // número de passagens
	Parallelism uint8
	SaltLen     uint32
	KeyLen      uint32
}

// DefaultParams segue o piso recomendado pela OWASP (m=19456 KiB = 19 MiB,
// t=2, p=1). Calibrar para ~250–500 ms no hardware de produção e elevar via
// configuração; hashes antigos continuam válidos e são regerados no login.
func DefaultParams() Params {
	return Params{Memory: 19456, Time: 2, Parallelism: 1, SaltLen: 16, KeyLen: 32}
}

func (p Params) valid() error {
	switch {
	case p.Memory < 8*1024:
		return errors.New("password: memória do Argon2id abaixo do mínimo seguro (8 MiB)")
	case p.Time < 1:
		return errors.New("password: Time deve ser >= 1")
	case p.Parallelism < 1:
		return errors.New("password: Parallelism deve ser >= 1")
	case p.SaltLen < 16:
		return errors.New("password: salt deve ter >= 16 bytes")
	case p.KeyLen < 16:
		return errors.New("password: KeyLen deve ser >= 16 bytes")
	}
	return nil
}

// Pepper aplica um segredo mantido fora do banco (KMS/Vault) à senha, antes do
// Argon2id. Versionado para permitir rotação: a versão vai gravada no hash.
type Pepper interface {
	// Apply devolve HMAC-SHA256(chave_da_versão, senha) e a versão usada.
	// version 0 é reservado para "sem pepper".
	Apply(password []byte) (peppered []byte, version uint16, err error)
	// ApplyVersion reaplica uma versão específica (para verificar um hash antigo).
	ApplyVersion(password []byte, version uint16) ([]byte, error)
}

// Hasher gera e verifica hashes de senha.
type Hasher struct {
	params Params
	pepper Pepper
	rand   func([]byte) (int, error)
}

// Option ajusta o Hasher.
type Option func(*Hasher)

// WithParams troca os parâmetros do Argon2id.
func WithParams(p Params) Option { return func(h *Hasher) { h.params = p } }

// WithRand troca a fonte de salt (para testes).
func WithRand(f func([]byte) (int, error)) Option { return func(h *Hasher) { h.rand = f } }

// NewHasher cria o Hasher. pepper pode ser nil (não recomendado em produção;
// aceito para desenvolvimento e testes).
func NewHasher(pepper Pepper, opts ...Option) (*Hasher, error) {
	h := &Hasher{params: DefaultParams(), pepper: pepper, rand: cryptoRandRead}
	for _, o := range opts {
		o(h)
	}
	if err := h.params.valid(); err != nil {
		return nil, err
	}
	return h, nil
}

// Hash deriva o hash PHC da senha. A senha em claro não é retida.
func (h *Hasher) Hash(plain []byte) (string, error) {
	salt := make([]byte, h.params.SaltLen)
	if _, err := h.rand(salt); err != nil {
		return "", fmt.Errorf("password: gerar salt: %w", err)
	}
	peppered, version, err := h.applyPepper(plain)
	if err != nil {
		return "", err
	}
	defer clear(peppered)
	key := argon2.IDKey(peppered, salt, h.params.Time, h.params.Memory, h.params.Parallelism, h.params.KeyLen)
	defer clear(key)
	return encode(h.params, version, salt, key), nil
}

// Verify confere a senha contra o hash. needsRehash é true quando o hash é
// válido mas usa parâmetros ou versão de pepper diferentes dos atuais: o
// chamador deve regerar o hash (tem a senha em claro em mãos no login).
func (h *Hasher) Verify(plain []byte, encoded string) (ok bool, needsRehash bool, err error) {
	p, version, salt, want, err := decode(encoded)
	if err != nil {
		return false, false, err
	}
	peppered, err := h.pepperForVerify(plain, version)
	if err != nil {
		return false, false, err
	}
	defer clear(peppered)
	got := argon2.IDKey(peppered, salt, p.Time, p.Memory, p.Parallelism, p.KeyLen)
	defer clear(got)
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return false, false, nil
	}
	return true, h.outdated(p, version), nil
}

func (h *Hasher) outdated(p Params, version uint16) bool {
	if p != h.params {
		return true
	}
	// Versão de pepper diferente da atual pede rehash. Descobrimos a versão
	// atual aplicando a uma senha vazia (barato) uma vez.
	if h.pepper != nil {
		_, cur, err := h.pepper.Apply(nil)
		if err == nil && cur != version {
			return true
		}
	} else if version != 0 {
		return true
	}
	return false
}

func (h *Hasher) applyPepper(plain []byte) ([]byte, uint16, error) {
	if h.pepper == nil {
		return append([]byte(nil), plain...), 0, nil
	}
	return h.pepper.Apply(plain)
}

func (h *Hasher) pepperForVerify(plain []byte, version uint16) ([]byte, error) {
	if version == 0 {
		return append([]byte(nil), plain...), nil
	}
	if h.pepper == nil {
		return nil, errors.New("password: hash exige pepper, mas nenhum foi configurado")
	}
	return h.pepper.ApplyVersion(plain, version)
}

// --- formato PHC -----------------------------------------------------------
// $argon2id$v=19$m=<mem>,t=<time>,p=<par>,k=<pepperVer>$<salt b64>$<hash b64>

var b64 = base64.RawStdEncoding

func encode(p Params, version uint16, salt, key []byte) string {
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d,k=%d$%s$%s",
		argon2.Version, p.Memory, p.Time, p.Parallelism, version,
		b64.EncodeToString(salt), b64.EncodeToString(key))
}

func decode(s string) (p Params, version uint16, salt, key []byte, err error) {
	parts := strings.Split(s, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return p, 0, nil, nil, fmt.Errorf("%w: formato de hash não reconhecido", ErrMismatch)
	}
	var ver int
	if _, err = fmt.Sscanf(parts[2], "v=%d", &ver); err != nil || ver != argon2.Version {
		return p, 0, nil, nil, fmt.Errorf("%w: versão do argon2 inesperada", ErrMismatch)
	}
	var k uint16
	if _, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d,k=%d", &p.Memory, &p.Time, &p.Parallelism, &k); err != nil {
		return p, 0, nil, nil, fmt.Errorf("password: parâmetros inválidos: %w", err)
	}
	if salt, err = b64.DecodeString(parts[4]); err != nil {
		return p, 0, nil, nil, fmt.Errorf("password: salt inválido: %w", err)
	}
	if key, err = b64.DecodeString(parts[5]); err != nil {
		return p, 0, nil, nil, fmt.Errorf("password: hash inválido: %w", err)
	}
	p.SaltLen = uint32(len(salt)) //nolint:gosec // tamanho de salt é pequeno
	p.KeyLen = uint32(len(key))   //nolint:gosec // tamanho de hash é pequeno
	return p, k, salt, key, nil
}

// --- pepper HMAC ------------------------------------------------------------

// HMACPepper implementa Pepper com chaves versionadas (HMAC-SHA256). As chaves
// vêm do KMS/Vault; nunca ficam em código ou em variável de ambiente em claro.
type HMACPepper struct {
	current uint16
	keys    map[uint16][]byte
}

// NewHMACPepper cria o pepper. keys mapeia versão→chave; current é a versão
// usada para hashes novos. Chaves com menos de 32 bytes são recusadas.
func NewHMACPepper(current uint16, keys map[uint16][]byte) (*HMACPepper, error) {
	if current == 0 {
		return nil, errors.New("password: versão 0 é reservada para 'sem pepper'")
	}
	if _, ok := keys[current]; !ok {
		return nil, errors.New("password: chave da versão atual ausente")
	}
	cp := make(map[uint16][]byte, len(keys))
	for v, k := range keys {
		if v == 0 {
			return nil, errors.New("password: versão 0 é reservada")
		}
		if len(k) < 32 {
			return nil, fmt.Errorf("password: chave de pepper da versão %d tem menos de 32 bytes", v)
		}
		cp[v] = append([]byte(nil), k...)
	}
	return &HMACPepper{current: current, keys: cp}, nil
}

func (p *HMACPepper) Apply(plain []byte) ([]byte, uint16, error) {
	out, err := p.ApplyVersion(plain, p.current)
	return out, p.current, err
}

func (p *HMACPepper) ApplyVersion(plain []byte, version uint16) ([]byte, error) {
	key, ok := p.keys[version]
	if !ok {
		return nil, fmt.Errorf("password: chave de pepper da versão %d não disponível", version)
	}
	m := hmac.New(sha256.New, key)
	m.Write(plain)
	return m.Sum(nil), nil
}
