-- Ciclo de vida do tenant (Fase 2b). Criar um tenant não exige função
-- privilegiada: a transação define app.tenant_id com o ID novo e a política
-- RLS (WITH CHECK id = core.current_tenant()) permite o INSERT.

-- +goose Up
ALTER TABLE core.tenants
  ADD COLUMN status text NOT NULL DEFAULT 'ativo' CHECK (status IN ('ativo', 'suspenso')),
  ADD COLUMN created_by uuid REFERENCES ident.users (id) ON DELETE SET NULL;

GRANT INSERT, UPDATE ON core.tenants TO app_rw;

-- +goose Down
REVOKE INSERT, UPDATE ON core.tenants FROM app_rw;
ALTER TABLE core.tenants DROP COLUMN created_by, DROP COLUMN status;
