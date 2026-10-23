-- Passkeys / WebAuthn (ADR-0007, item 5). Só dados públicos: a chave pública e
-- metadados do autenticador. A chave privada nunca sai do dispositivo do
-- usuário, então o vazamento desta tabela não permite autenticar ninguém.

-- +goose Up
CREATE TABLE ident.webauthn_credentials (
  credential_id bytea PRIMARY KEY,
  user_id       uuid NOT NULL REFERENCES ident.users (id) ON DELETE CASCADE,
  -- webauthn.Credential serializado (chave pública, flags, contador, AAGUID).
  credential    jsonb NOT NULL,
  label         text NOT NULL DEFAULT '' CHECK (length(label) <= 100),
  created_at    timestamptz NOT NULL DEFAULT now(),
  last_used_at  timestamptz
);
CREATE INDEX webauthn_credentials_user_idx ON ident.webauthn_credentials (user_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON ident.webauthn_credentials TO app_rw;

-- +goose Down
DROP TABLE ident.webauthn_credentials;
