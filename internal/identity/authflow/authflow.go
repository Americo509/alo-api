// Package authflow orquestra cadastro, verificação de e-mail, login por senha,
// recuperação e troca de senha (ADR-0007, itens 2 e 3), com defesa contra
// enumeração de contas: as operações que recebem um e-mail respondem de forma
// uniforme exista ou não a conta, e o login iguala o tempo de resposta.
package authflow

import (
	"context"
	"crypto/rand"
	"errors"
	"log/slog"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/Americo509/alo-api/internal/identity"
	"github.com/Americo509/alo-api/internal/identity/authtoken"
	"github.com/Americo509/alo-api/internal/identity/pwpolicy"
	"github.com/Americo509/alo-api/internal/storage/postgres"
)

// ErrInvalidCredentials é o único erro de login: não distingue "usuário não
// existe" de "senha errada".
var ErrInvalidCredentials = errors.New("authflow: e-mail ou senha incorretos")

// Hasher é o que o fluxo precisa do pacote password.
type Hasher interface {
	Hash(plain []byte) (string, error)
	Verify(plain []byte, encoded string) (ok bool, needsRehash bool, err error)
}

// Store é o acesso a usuários e senhas. identity.Repo satisfaz.
type Store interface {
	GetUserByEmail(ctx context.Context, email string) (identity.User, error)
	GetUser(ctx context.Context, id uuid.UUID) (identity.User, error)
	GetPassword(ctx context.Context, id uuid.UUID) (string, error)
	SetPassword(ctx context.Context, id uuid.UUID, phc string) error
	CreateUser(ctx context.Context, email, displayName string, verified bool) (identity.User, error)
	SetEmailVerified(ctx context.Context, id uuid.UUID) error
}

// Tokens emite e consome tokens de uso único. authtoken.Service satisfaz.
type Tokens interface {
	Issue(ctx context.Context, userID uuid.UUID, p authtoken.Purpose) (string, error)
	Consume(ctx context.Context, token string, p authtoken.Purpose) (uuid.UUID, error)
	InvalidateAll(ctx context.Context, userID uuid.UUID, p authtoken.Purpose) error
}

// Atomic executa fn numa transação, com o Store e os Tokens ligados a ela:
// ou tudo acontece, ou nada.
type Atomic interface {
	Do(ctx context.Context, fn func(Store, Tokens) error) error
}

// PGAtomic implementa Atomic sobre uma transação do Postgres.
type PGAtomic struct {
	pool   postgres.Beginner
	tokens *authtoken.Service
}

// NewPGAtomic cria o Atomic do Postgres.
func NewPGAtomic(pool postgres.Beginner, tokens *authtoken.Service) *PGAtomic {
	return &PGAtomic{pool: pool, tokens: tokens}
}

// Do implementa Atomic.
func (a *PGAtomic) Do(ctx context.Context, fn func(Store, Tokens) error) error {
	return pgx.BeginTxFunc(ctx, a.pool, pgx.TxOptions{}, func(tx pgx.Tx) error {
		return fn(identity.NewRepo(tx), a.tokens.WithDB(tx))
	})
}

// Service reúne as dependências dos fluxos de autenticação.
type Service struct {
	store  Store
	tokens Tokens
	atomic Atomic
	hasher Hasher
	policy pwpolicy.Policy
	mailer Mailer
	log    *slog.Logger
	// dummyHash é um hash válido usado para igualar o tempo do login quando o
	// usuário não existe (evita oráculo de tempo).
	dummyHash string
}

// Deps são as dependências injetadas.
type Deps struct {
	Store  Store
	Tokens Tokens
	Atomic Atomic
	Hasher Hasher
	Policy pwpolicy.Policy
	Mailer Mailer
	Log    *slog.Logger
}

// New cria o serviço e pré-computa o hash fictício do login.
func New(d Deps) (*Service, error) {
	if d.Store == nil || d.Tokens == nil || d.Atomic == nil || d.Hasher == nil || d.Mailer == nil {
		return nil, errors.New("authflow: dependências obrigatórias ausentes")
	}
	log := d.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	// Senha aleatória longa só para gerar um hash de referência de tempo.
	ref := make([]byte, 32)
	if _, err := rand.Read(ref); err != nil {
		return nil, err
	}
	dummy, err := d.Hasher.Hash(ref)
	if err != nil {
		return nil, err
	}
	return &Service{
		store: d.Store, tokens: d.Tokens, atomic: d.Atomic,
		hasher: d.Hasher, policy: d.Policy, mailer: d.Mailer, log: log, dummyHash: dummy,
	}, nil
}

// Register cadastra um usuário por e-mail e senha. NÃO revela se o e-mail já
// existe: sempre devolve nil e, por e-mail, manda verificação (conta nova) ou
// aviso de conta existente. A validação de senha e formato de e-mail acontece
// antes, porque o próprio usuário informou esses dados.
func (s *Service) Register(ctx context.Context, rawEmail, rawPassword string) error {
	email, err := identity.NormalizeEmail(rawEmail)
	if err != nil {
		return err
	}
	pw := pwpolicy.Normalize(rawPassword)
	if err := s.policy.Validate(ctx, pw); err != nil {
		return err
	}
	phc, err := s.hasher.Hash([]byte(pw))
	if err != nil {
		return err
	}

	var newUserID uuid.UUID
	var existing bool
	err = s.atomic.Do(ctx, func(st Store, _ Tokens) error {
		u, err := st.CreateUser(ctx, email, "", false)
		if errors.Is(err, identity.ErrEmailTaken) {
			existing = true
			return nil
		}
		if err != nil {
			return err
		}
		newUserID = u.ID
		return st.SetPassword(ctx, u.ID, phc)
	})
	if err != nil {
		return err
	}

	if existing {
		// Aviso para o dono do e-mail; a quem fez a requisição, resposta idêntica.
		if err := s.mailer.SendAccountExists(ctx, email); err != nil {
			s.log.Warn("falha ao enviar aviso de conta existente", slog.Any("erro", err))
		}
		return nil
	}
	return s.issueAndSendVerification(ctx, newUserID, email)
}

func (s *Service) issueAndSendVerification(ctx context.Context, userID uuid.UUID, email string) error {
	token, err := s.tokens.Issue(ctx, userID, authtoken.PurposeEmailVerification)
	if err != nil {
		return err
	}
	if err := s.mailer.SendEmailVerification(ctx, email, token); err != nil {
		s.log.Warn("falha ao enviar verificação de e-mail", slog.Any("erro", err))
	}
	return nil
}

// VerifyEmail consome o token e marca o e-mail como verificado.
func (s *Service) VerifyEmail(ctx context.Context, token string) error {
	return s.atomic.Do(ctx, func(st Store, tk Tokens) error {
		userID, err := tk.Consume(ctx, token, authtoken.PurposeEmailVerification)
		if err != nil {
			return err
		}
		return st.SetEmailVerified(ctx, userID)
	})
}

// Login valida e-mail e senha. Erro único (ErrInvalidCredentials) e tempo
// igualado por um hash fictício quando o usuário não existe. Devolve o usuário
// e se a senha precisa ser re-hasheada (o chamador chama Rehash, pois tem a
// senha em claro em mãos).
func (s *Service) Login(ctx context.Context, rawEmail, rawPassword string) (identity.User, bool, error) {
	email, err := identity.NormalizeEmail(rawEmail)
	if err != nil {
		// Mesmo com e-mail malformado, paga o custo de um verify para não criar
		// oráculo de tempo, e devolve o erro genérico.
		_, _, _ = s.hasher.Verify([]byte("x"), s.dummyHash)
		return identity.User{}, false, ErrInvalidCredentials
	}
	pw := pwpolicy.Normalize(rawPassword)

	u, err := s.store.GetUserByEmail(ctx, email)
	if errors.Is(err, identity.ErrNotFound) {
		_, _, _ = s.hasher.Verify([]byte(pw), s.dummyHash)
		return identity.User{}, false, ErrInvalidCredentials
	} else if err != nil {
		return identity.User{}, false, err
	}
	phc, err := s.store.GetPassword(ctx, u.ID)
	if errors.Is(err, identity.ErrNoPassword) {
		_, _, _ = s.hasher.Verify([]byte(pw), s.dummyHash)
		return identity.User{}, false, ErrInvalidCredentials
	} else if err != nil {
		return identity.User{}, false, err
	}
	ok, needsRehash, err := s.hasher.Verify([]byte(pw), phc)
	if err != nil {
		return identity.User{}, false, err
	}
	if !ok || !u.CanLogIn() {
		return identity.User{}, false, ErrInvalidCredentials
	}
	return u, needsRehash, nil
}

// VerifyPassword confere a senha de um usuário JÁ identificado (reautenticação
// antes de ações sensíveis). ErrInvalidCredentials se não conferir.
func (s *Service) VerifyPassword(ctx context.Context, userID uuid.UUID, rawPassword string) error {
	pw := pwpolicy.Normalize(rawPassword)
	phc, err := s.store.GetPassword(ctx, userID)
	if errors.Is(err, identity.ErrNoPassword) {
		_, _, _ = s.hasher.Verify([]byte(pw), s.dummyHash)
		return ErrInvalidCredentials
	} else if err != nil {
		return err
	}
	ok, _, err := s.hasher.Verify([]byte(pw), phc)
	if err != nil {
		return err
	}
	if !ok {
		return ErrInvalidCredentials
	}
	return nil
}

// Rehash regrava o hash da senha com os parâmetros atuais. Chamar só depois de
// uma verificação bem-sucedida que sinalizou needsRehash.
func (s *Service) Rehash(ctx context.Context, userID uuid.UUID, rawPassword string) error {
	phc, err := s.hasher.Hash([]byte(pwpolicy.Normalize(rawPassword)))
	if err != nil {
		return err
	}
	return s.store.SetPassword(ctx, userID, phc)
}

// ChangePassword troca a senha de um usuário autenticado, exigindo a senha
// atual. Invalida recuperações pendentes e avisa por e-mail. O chamador deve
// encerrar as outras sessões.
func (s *Service) ChangePassword(ctx context.Context, userID uuid.UUID, current, next string) error {
	if err := s.VerifyPassword(ctx, userID, current); err != nil {
		return err
	}
	pw := pwpolicy.Normalize(next)
	if err := s.policy.Validate(ctx, pw); err != nil {
		return err
	}
	phc, err := s.hasher.Hash([]byte(pw))
	if err != nil {
		return err
	}
	var email string
	err = s.atomic.Do(ctx, func(st Store, tk Tokens) error {
		if err := st.SetPassword(ctx, userID, phc); err != nil {
			return err
		}
		if err := tk.InvalidateAll(ctx, userID, authtoken.PurposePasswordRecovery); err != nil {
			return err
		}
		u, err := st.GetUser(ctx, userID)
		email = u.Email
		return err
	})
	if err != nil {
		return err
	}
	if err := s.mailer.SendPasswordChanged(ctx, email); err != nil {
		s.log.Warn("falha ao avisar troca de senha", slog.Any("erro", err))
	}
	return nil
}

// StartPasswordRecovery sempre devolve nil (anti-enumeração): só envia o e-mail
// de recuperação se a conta existir.
func (s *Service) StartPasswordRecovery(ctx context.Context, rawEmail string) error {
	email, err := identity.NormalizeEmail(rawEmail)
	if err != nil {
		return nil //nolint:nilerr // anti-enumeração: não revela e-mail inválido
	}
	u, err := s.store.GetUserByEmail(ctx, email)
	if errors.Is(err, identity.ErrNotFound) {
		return nil
	} else if err != nil {
		return err
	}
	token, err := s.tokens.Issue(ctx, u.ID, authtoken.PurposePasswordRecovery)
	if err != nil {
		return err
	}
	if err := s.mailer.SendPasswordRecovery(ctx, email, token); err != nil {
		s.log.Warn("falha ao enviar recuperação de senha", slog.Any("erro", err))
	}
	return nil
}

// CompletePasswordRecovery troca a senha usando o token, revoga as demais
// recuperações pendentes e avisa o usuário. O chamador deve encerrar as outras
// sessões (RevokeAll) — isso é feito na borda, que tem o session.Manager.
func (s *Service) CompletePasswordRecovery(ctx context.Context, token, rawNewPassword string) (userID uuid.UUID, err error) {
	pw := pwpolicy.Normalize(rawNewPassword)
	if err := s.policy.Validate(ctx, pw); err != nil {
		return uuid.Nil, err
	}
	phc, err := s.hasher.Hash([]byte(pw))
	if err != nil {
		return uuid.Nil, err
	}
	var email string
	err = s.atomic.Do(ctx, func(st Store, tk Tokens) error {
		uid, err := tk.Consume(ctx, token, authtoken.PurposePasswordRecovery)
		if err != nil {
			return err
		}
		userID = uid
		if err := st.SetPassword(ctx, uid, phc); err != nil {
			return err
		}
		if err := tk.InvalidateAll(ctx, uid, authtoken.PurposePasswordRecovery); err != nil {
			return err
		}
		u, err := st.GetUser(ctx, uid)
		if err != nil {
			return err
		}
		email = u.Email
		return nil
	})
	if err != nil {
		return uuid.Nil, err
	}
	if err := s.mailer.SendPasswordChanged(ctx, email); err != nil {
		s.log.Warn("falha ao avisar troca de senha", slog.Any("erro", err))
	}
	return userID, nil
}
