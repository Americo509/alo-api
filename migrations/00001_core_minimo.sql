-- Núcleo multi-tenant mínimo para a Fase 1. A Fase 2 amplia (usuários, papéis,
-- planos). Regras de isolamento: ADR-0006.

-- +goose Up
CREATE SCHEMA core;

-- Papel sem login usado pelos serviços. Não é dono de nada e não ignora RLS.
-- A credencial de login (membro deste papel) é criada pela operação.
-- +goose StatementBegin
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_rw') THEN
    CREATE ROLE app_rw NOLOGIN NOBYPASSRLS;
  END IF;
END
$$;
-- +goose StatementEnd

-- Tenant da transação atual. Sem app.tenant_id definido, a função FALHA (não
-- devolve vazio): query sem tenant é erro, não resultado vazio (ADR-0006, item 5).
-- +goose StatementBegin
CREATE FUNCTION core.current_tenant() RETURNS uuid
LANGUAGE sql STABLE PARALLEL SAFE
AS $$ SELECT current_setting('app.tenant_id')::uuid $$;
-- +goose StatementEnd

CREATE TABLE core.tenants (
  id         uuid PRIMARY KEY,
  name       text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE core.instances (
  id         uuid PRIMARY KEY,
  tenant_id  uuid NOT NULL REFERENCES core.tenants (id) ON DELETE RESTRICT,
  status     text NOT NULL DEFAULT 'DESCONECTADA'
             CHECK (status IN ('DESCONECTADA', 'PAREANDO', 'CONECTADA', 'DEGRADADA', 'BANIDA')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  -- Alvo das FKs compostas: garante que dado de uma instância nunca é gravado
  -- com tenant_id de outro tenant.
  UNIQUE (id, tenant_id)
);
CREATE INDEX instances_tenant_idx ON core.instances (tenant_id);

ALTER TABLE core.tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.tenants FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON core.tenants
  USING (id = core.current_tenant()) WITH CHECK (id = core.current_tenant());

ALTER TABLE core.instances ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.instances FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON core.instances
  USING (tenant_id = core.current_tenant()) WITH CHECK (tenant_id = core.current_tenant());

GRANT USAGE ON SCHEMA core TO app_rw;
GRANT EXECUTE ON FUNCTION core.current_tenant() TO app_rw;
GRANT SELECT ON core.tenants TO app_rw;
GRANT SELECT, INSERT, UPDATE ON core.instances TO app_rw;

-- +goose Down
DROP SCHEMA core CASCADE;
