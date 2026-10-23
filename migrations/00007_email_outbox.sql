-- Fila de e-mails transacionais (outbox). O conteúdo (que traz links com tokens
-- de uso único) fica CIFRADO e é apagado quando o e-mail sai ou morre.

-- +goose Up
CREATE TABLE ident.email_outbox (
  id           uuid PRIMARY KEY,
  kind         text NOT NULL,
  payload_enc  bytea,                      -- NULL depois de morto
  attempts     integer NOT NULL DEFAULT 0,
  available_at timestamptz NOT NULL,
  locked_until timestamptz,
  expires_at   timestamptz NOT NULL,
  dead         boolean NOT NULL DEFAULT false,
  dead_at      timestamptz,
  -- Só uma CLASSE curta de erro ("smtp", "mensagem_invalida"), nunca texto livre:
  -- mensagens de erro de SMTP podem conter o endereço do destinatário.
  last_error   text NOT NULL DEFAULT '' CHECK (length(last_error) <= 40),
  created_at   timestamptz NOT NULL DEFAULT now(),
  CHECK (dead OR payload_enc IS NOT NULL)
);
CREATE INDEX email_outbox_ready_idx ON ident.email_outbox (available_at) WHERE dead = false;
CREATE INDEX email_outbox_dead_idx ON ident.email_outbox (dead_at) WHERE dead = true;

GRANT SELECT, INSERT, UPDATE, DELETE ON ident.email_outbox TO app_rw;

-- +goose Down
DROP TABLE ident.email_outbox;
