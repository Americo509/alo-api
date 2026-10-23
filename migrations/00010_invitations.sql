-- Convites de membros (Fase 2b). O token vai por e-mail e aqui fica só o hash
-- SHA-256. Um convite vale para UM e-mail: quem aceita precisa ter esse e-mail
-- verificado, então um link encaminhado não dá acesso a outra pessoa.

-- +goose Up
CREATE TABLE ident.invitations (
  id          uuid PRIMARY KEY,
  tenant_id   uuid NOT NULL REFERENCES core.tenants (id) ON DELETE CASCADE,
  email       text NOT NULL,
  role        text NOT NULL CHECK (role IN ('dono', 'admin', 'operador', 'leitura')),
  token_hash  bytea NOT NULL UNIQUE CHECK (length(token_hash) = 32),
  invited_by  uuid REFERENCES ident.users (id) ON DELETE SET NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz NOT NULL,
  accepted_at timestamptz,
  revoked_at  timestamptz
);
-- No máximo um convite pendente por (tenant, e-mail).
CREATE UNIQUE INDEX invitations_pending_uniq ON ident.invitations (tenant_id, lower(email))
  WHERE accepted_at IS NULL AND revoked_at IS NULL;
CREATE INDEX invitations_tenant_idx ON ident.invitations (tenant_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON ident.invitations TO app_rw;

-- +goose Down
DROP TABLE ident.invitations;
