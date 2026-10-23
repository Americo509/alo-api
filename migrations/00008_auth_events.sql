-- Registro de eventos de segurança de autenticação (ADR-0007, item 9).
-- Append-only: UPDATE é bloqueado por gatilho. O IP e o User-Agent ficam
-- cifrados em detail_enc. A exclusão por retenção é feita por uma role própria,
-- a app_rw só lê e insere.

-- +goose Up
CREATE TABLE ident.auth_events (
  id         uuid PRIMARY KEY,
  -- SET NULL: ao excluir o usuário (LGPD) o evento permanece, sem o vínculo,
  -- pelo prazo de guarda legal do registro de acesso (Marco Civil, art. 15).
  user_id    uuid REFERENCES ident.users (id) ON DELETE SET NULL,
  event      text NOT NULL CHECK (length(event) <= 60),
  at         timestamptz NOT NULL,
  detail_enc bytea NOT NULL
);
CREATE INDEX auth_events_user_idx ON ident.auth_events (user_id, at DESC);
CREATE INDEX auth_events_at_idx ON ident.auth_events (at);

-- Imutabilidade: nenhuma coluna pode mudar, exceto user_id -> NULL (que é a ação
-- ON DELETE SET NULL da chave estrangeira).
-- +goose StatementBegin
CREATE FUNCTION ident.auth_events_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.id = OLD.id AND NEW.event = OLD.event AND NEW.at = OLD.at
     AND NEW.detail_enc = OLD.detail_enc
     AND NEW.user_id IS NULL AND OLD.user_id IS NOT NULL THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'ident.auth_events é append-only';
END
$$;
-- +goose StatementEnd
CREATE TRIGGER auth_events_immutable BEFORE UPDATE ON ident.auth_events
  FOR EACH ROW EXECUTE FUNCTION ident.auth_events_immutable();

-- +goose StatementBegin
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_retention') THEN
    CREATE ROLE app_retention NOLOGIN NOBYPASSRLS;
  END IF;
END
$$;
-- +goose StatementEnd

GRANT SELECT, INSERT ON ident.auth_events TO app_rw;
GRANT USAGE ON SCHEMA ident TO app_retention;
GRANT SELECT, DELETE ON ident.auth_events TO app_retention;

-- +goose Down
DROP TABLE ident.auth_events;
DROP FUNCTION ident.auth_events_immutable();
