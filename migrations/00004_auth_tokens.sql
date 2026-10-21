-- Tokens de uso único para verificação de e-mail e recuperação de senha
-- (ADR-0007, item 3). Guardados SÓ como hash SHA-256: um dump da tabela não
-- permite usar nenhum link. São revogáveis (por isso não são JWT) e expiram.

-- +goose Up
CREATE TABLE ident.auth_tokens (
  token_hash bytea PRIMARY KEY CHECK (length(token_hash) = 32),
  user_id    uuid NOT NULL REFERENCES ident.users (id) ON DELETE CASCADE,
  purpose    text NOT NULL CHECK (purpose IN ('verificacao_email', 'recuperacao_senha')),
  created_at timestamptz NOT NULL DEFAULT now(),
  expires_at timestamptz NOT NULL,
  used_at    timestamptz
);
CREATE INDEX auth_tokens_user_purpose_idx ON ident.auth_tokens (user_id, purpose);
CREATE INDEX auth_tokens_expires_idx ON ident.auth_tokens (expires_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON ident.auth_tokens TO app_rw;

-- +goose Down
DROP TABLE ident.auth_tokens;
