// Package pwpolicy aplica a política de senha do NIST SP 800-63B (ADR-0007,
// item 2): comprimento mínimo configurável, aceitar textos longos e qualquer
// caractere Unicode (normalizado NFKC), SEM regras de composição e SEM
// expiração periódica. Bloqueia senhas conhecidamente vazadas via um
// verificador plugável (k-anonimato).
package pwpolicy

import (
	"context"
	"errors"
	"fmt"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// Limites recomendados pelo NIST: mínimo 8 (usamos 12 por padrão), aceitar até
// 64+ (usamos 128); abaixo não truncar.
const (
	DefaultMinLength = 12
	MaxLength        = 128
)

var (
	// ErrTooShort / ErrTooLong / ErrBreached descrevem a reprovação. A borda
	// traduz para mensagem ao usuário; não revelam nada sensível.
	ErrTooShort = errors.New("pwpolicy: senha curta demais")
	ErrTooLong  = errors.New("pwpolicy: senha longa demais")
	ErrBreached = errors.New("pwpolicy: senha apareceu em vazamentos conhecidos")
)

// BreachChecker informa quantas vezes uma senha apareceu em vazamentos. A
// implementação não deve expor a senha (ver HIBP, k-anonimato).
type BreachChecker interface {
	// TimesSeen devolve 0 se a senha não consta. Em caso de erro de I/O, o
	// chamador decide a política de falha (ver Policy.FailOpen).
	TimesSeen(ctx context.Context, password string) (int, error)
}

// Policy valida senhas.
type Policy struct {
	MinLength int
	Breach    BreachChecker
	// FailOpen: se o verificador de vazamento falhar (serviço fora), aceita a
	// senha (true) em vez de barrar (false). Padrão true: não travar o cadastro
	// por indisponibilidade externa; o ADR aceita reavaliar no próximo login.
	FailOpen bool
}

// New cria a política com o mínimo padrão e fail-open.
func New(breach BreachChecker) Policy {
	return Policy{MinLength: DefaultMinLength, Breach: breach, FailOpen: true}
}

// Normalize prepara a senha para hash e contagem: NFKC, como o NIST recomenda,
// para que a mesma senha digitada de formas diferentes case.
func Normalize(password string) string { return norm.NFKC.String(password) }

// Validate checa a senha já normalizada (use Normalize antes de guardar e de
// validar, para serem coerentes). O comprimento é contado em caracteres, não
// em bytes.
func (p Policy) Validate(ctx context.Context, password string) error {
	min := p.MinLength
	if min == 0 {
		min = DefaultMinLength
	}
	n := utf8.RuneCountInString(password)
	switch {
	case n < min:
		return fmt.Errorf("%w: mínimo de %d caracteres", ErrTooShort, min)
	case len(password) > MaxLength*4 || n > MaxLength:
		// Teto generoso; evita abuso de CPU no hash sem truncar senhas legítimas.
		return ErrTooLong
	}
	if p.Breach != nil {
		seen, err := p.Breach.TimesSeen(ctx, password)
		switch {
		case err != nil && p.FailOpen:
			return nil
		case err != nil:
			return fmt.Errorf("pwpolicy: verificação de vazamento falhou: %w", err)
		case seen > 0:
			return ErrBreached
		}
	}
	return nil
}
