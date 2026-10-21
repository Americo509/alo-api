-- Identidade dos usuários humanos do painel (ADR-0007). Diferente do schema
-- wa/core (dados por tenant, com RLS), identidade é GLOBAL à plataforma: um
-- usuário pode pertencer a vários tenants. A autorização por tenant é feita na
-- aplicação, via tabela memberships, não por RLS.

-- +goose Up
CREATE SCHEMA ident;

CREATE TABLE ident.users (
  id             uuid PRIMARY KEY,
  -- E-mail normalizado (minúsculo, sem espaços). NUNCA é a chave de login
  -- social (essa é issuer+subject); serve para contato e vínculo verificado.
  email          text NOT NULL,
  email_verified boolean NOT NULL DEFAULT false,
  -- Nome de exibição; opcional (login social pode não informar).
  display_name   text NOT NULL DEFAULT '' CHECK (length(display_name) <= 200),
  status         text NOT NULL DEFAULT 'ativo' CHECK (status IN ('ativo', 'suspenso', 'desativado')),
  created_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now()
);
-- E-mail único entre usuários ativos; case-insensitive garantido pela
-- normalização na aplicação, reforçado aqui com lower().
CREATE UNIQUE INDEX users_email_uniq ON ident.users (lower(email));

-- Senha (opcional: usuário pode existir só com login social).
CREATE TABLE ident.user_password (
  user_id    uuid PRIMARY KEY REFERENCES ident.users (id) ON DELETE CASCADE,
  phc        text NOT NULL,          -- hash Argon2id no formato PHC (pacote password)
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- Identidades federadas (Google, Apple, ...). Chave = (issuer, subject).
CREATE TABLE ident.user_identities (
  id         uuid PRIMARY KEY,
  user_id    uuid NOT NULL REFERENCES ident.users (id) ON DELETE CASCADE,
  issuer     text NOT NULL,   -- ex.: https://accounts.google.com
  subject    text NOT NULL,   -- 'sub' do provedor; estável por usuário
  email      text,            -- e-mail informado pelo provedor na vinculação
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (issuer, subject)
);
CREATE INDEX user_identities_user_idx ON ident.user_identities (user_id);

-- Vínculo usuário↔tenant com papel. É o que decide o que cada usuário pode
-- fazer em cada tenant.
CREATE TABLE ident.memberships (
  user_id    uuid NOT NULL REFERENCES ident.users (id) ON DELETE CASCADE,
  tenant_id  uuid NOT NULL REFERENCES core.tenants (id) ON DELETE CASCADE,
  role       text NOT NULL CHECK (role IN ('dono', 'admin', 'operador', 'leitura')),
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, tenant_id)
);
CREATE INDEX memberships_tenant_idx ON ident.memberships (tenant_id);

-- Admin da plataforma (você). Separado dos papéis de tenant (ADR-0008).
CREATE TABLE ident.platform_admins (
  user_id    uuid PRIMARY KEY REFERENCES ident.users (id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now()
);

GRANT USAGE ON SCHEMA ident TO app_rw;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA ident TO app_rw;

-- +goose Down
DROP SCHEMA ident CASCADE;
