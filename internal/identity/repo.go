package identity

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Erros de domínio da camada de identidade.
var (
	ErrNotFound    = errors.New("identity: usuário não encontrado")
	ErrEmailTaken  = errors.New("identity: e-mail já cadastrado")
	ErrNoPassword  = errors.New("identity: usuário não tem senha definida")
	ErrIdentityDup = errors.New("identity: identidade federada já vinculada a outro usuário")
)

// DB é o mínimo que o repositório precisa (pool ou transação).
type DB interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Repo acessa as tabelas do schema ident. Não abre transações próprias; quem
// precisa de atomicidade passa uma pgx.Tx como DB.
type Repo struct{ db DB }

// NewRepo cria o repositório sobre db.
func NewRepo(db DB) *Repo { return &Repo{db: db} }

// WithTx devolve um Repo que usa a transação dada.
func (r *Repo) WithTx(tx pgx.Tx) *Repo { return &Repo{db: tx} }

const userCols = `id, email, email_verified, display_name, status, created_at, updated_at`

func scanUser(row pgx.Row) (User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Email, &u.EmailVerified, &u.DisplayName, &u.Status, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

// CreateUser insere um usuário. email deve vir já normalizado.
func (r *Repo) CreateUser(ctx context.Context, email, displayName string, emailVerified bool) (User, error) {
	id := uuid.New()
	row := r.db.QueryRow(ctx, `
		INSERT INTO ident.users (id, email, email_verified, display_name)
		VALUES ($1, $2, $3, $4) RETURNING `+userCols,
		id, email, emailVerified, displayName)
	u, err := scanUser(row)
	if isUniqueViolation(err, "users_email_uniq") {
		return User{}, ErrEmailTaken
	}
	return u, err
}

// GetUser busca por ID.
func (r *Repo) GetUser(ctx context.Context, id uuid.UUID) (User, error) {
	return scanUser(r.db.QueryRow(ctx, `SELECT `+userCols+` FROM ident.users WHERE id = $1`, id))
}

// GetUserByEmail busca por e-mail normalizado (case-insensitive).
func (r *Repo) GetUserByEmail(ctx context.Context, email string) (User, error) {
	return scanUser(r.db.QueryRow(ctx, `SELECT `+userCols+` FROM ident.users WHERE lower(email) = lower($1)`, email))
}

// SetEmailVerified marca o e-mail como verificado.
func (r *Repo) SetEmailVerified(ctx context.Context, id uuid.UUID) error {
	return r.exec(ctx, `UPDATE ident.users SET email_verified = true, updated_at = now() WHERE id = $1`, id)
}

// --- senha -----------------------------------------------------------------

// SetPassword grava (ou substitui) o hash PHC da senha.
func (r *Repo) SetPassword(ctx context.Context, userID uuid.UUID, phc string) error {
	return r.exec(ctx, `
		INSERT INTO ident.user_password (user_id, phc) VALUES ($1, $2)
		ON CONFLICT (user_id) DO UPDATE SET phc = excluded.phc, updated_at = now()`,
		userID, phc)
}

// GetPassword devolve o hash PHC do usuário.
func (r *Repo) GetPassword(ctx context.Context, userID uuid.UUID) (string, error) {
	var phc string
	err := r.db.QueryRow(ctx, `SELECT phc FROM ident.user_password WHERE user_id = $1`, userID).Scan(&phc)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNoPassword
	}
	return phc, err
}

// --- identidades federadas -------------------------------------------------

// LinkIdentity vincula (issuer, subject) a um usuário.
func (r *Repo) LinkIdentity(ctx context.Context, userID uuid.UUID, issuer, subject, email string) (Identity, error) {
	id := Identity{ID: uuid.New(), UserID: userID, Issuer: issuer, Subject: subject, Email: email}
	_, err := r.db.Exec(ctx, `
		INSERT INTO ident.user_identities (id, user_id, issuer, subject, email) VALUES ($1, $2, $3, $4, $5)`,
		id.ID, userID, issuer, subject, email)
	if isUniqueViolation(err, "user_identities_issuer_subject_key") {
		return Identity{}, ErrIdentityDup
	}
	return id, err
}

// FindByIdentity busca o usuário vinculado a (issuer, subject).
func (r *Repo) FindByIdentity(ctx context.Context, issuer, subject string) (User, error) {
	return scanUser(r.db.QueryRow(ctx, `
		SELECT `+prefixCols("u", userCols)+`
		FROM ident.users u
		JOIN ident.user_identities i ON i.user_id = u.id
		WHERE i.issuer = $1 AND i.subject = $2`, issuer, subject))
}

// --- memberships -----------------------------------------------------------

// UpsertMembership cria ou atualiza o papel de um usuário num tenant.
func (r *Repo) UpsertMembership(ctx context.Context, m Membership) error {
	if !m.Role.Valid() {
		return fmt.Errorf("identity: papel inválido %q", m.Role)
	}
	return r.exec(ctx, `
		INSERT INTO ident.memberships (user_id, tenant_id, role) VALUES ($1, $2, $3)
		ON CONFLICT (user_id, tenant_id) DO UPDATE SET role = excluded.role`,
		m.UserID, m.TenantID, m.Role)
}

// Membership devolve o vínculo de um usuário num tenant (ErrNotFound se não há).
func (r *Repo) Membership(ctx context.Context, userID, tenantID uuid.UUID) (Membership, error) {
	var m Membership
	err := r.db.QueryRow(ctx, `SELECT user_id, tenant_id, role FROM ident.memberships WHERE user_id = $1 AND tenant_id = $2`,
		userID, tenantID).Scan(&m.UserID, &m.TenantID, &m.Role)
	if errors.Is(err, pgx.ErrNoRows) {
		return Membership{}, ErrNotFound
	}
	return m, err
}

// MembershipsOf lista os vínculos de um usuário.
func (r *Repo) MembershipsOf(ctx context.Context, userID uuid.UUID) ([]Membership, error) {
	rows, err := r.db.Query(ctx, `SELECT user_id, tenant_id, role FROM ident.memberships WHERE user_id = $1 ORDER BY created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Membership
	for rows.Next() {
		var m Membership
		if err := rows.Scan(&m.UserID, &m.TenantID, &m.Role); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// IsPlatformAdmin informa se o usuário é admin da plataforma.
func (r *Repo) IsPlatformAdmin(ctx context.Context, userID uuid.UUID) (bool, error) {
	var ok bool
	err := r.db.QueryRow(ctx, `SELECT true FROM ident.platform_admins WHERE user_id = $1`, userID).Scan(&ok)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return ok, err
}

// --- helpers ---------------------------------------------------------------

func (r *Repo) exec(ctx context.Context, sql string, args ...any) error {
	_, err := r.db.Exec(ctx, sql, args...)
	return err
}

func prefixCols(alias, cols string) string {
	parts := strings.Split(cols, ", ")
	for i, c := range parts {
		parts[i] = alias + "." + c
	}
	return strings.Join(parts, ", ")
}

func isUniqueViolation(err error, constraint string) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505" && (constraint == "" || pgErr.ConstraintName == constraint)
}
