-- Segundo fator (ADR-0007, item 5): TOTP (RFC 6238) e códigos de recuperação.
-- O segredo TOTP é cifrado com a chave de MFA da plataforma (envelope, AAD =
-- user_id); os códigos de recuperação guardam só o hash.

-- +goose Up
CREATE TABLE ident.mfa_totp (
  user_id      uuid PRIMARY KEY REFERENCES ident.users (id) ON DELETE CASCADE,
  secret_enc   bytea NOT NULL,
  -- confirmed_at nulo = inscrição iniciada mas ainda não confirmada por um
  -- código válido; o fator só vale depois de confirmado.
  confirmed_at timestamptz,
  -- last_step: maior passo de tempo já aceito; impede reuso do mesmo código
  -- (e de códigos de passos anteriores) dentro da janela.
  last_step    bigint NOT NULL DEFAULT 0,
  created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE ident.recovery_codes (
  user_id    uuid NOT NULL REFERENCES ident.users (id) ON DELETE CASCADE,
  code_hash  bytea NOT NULL CHECK (length(code_hash) = 32),
  used_at    timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, code_hash)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON ident.mfa_totp TO app_rw;
GRANT SELECT, INSERT, UPDATE, DELETE ON ident.recovery_codes TO app_rw;

-- +goose Down
DROP TABLE ident.recovery_codes;
DROP TABLE ident.mfa_totp;
