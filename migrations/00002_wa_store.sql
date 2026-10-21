-- Store cifrado do estado da sessão do WhatsApp (ADR-0010).
--
-- Convenções:
--   *_enc  bytea: cifrado com a chave da instância (AES-256-GCM, AAD amarrado
--                 a instância + tabela + chave lógica). Nunca em claro.
--   *_idx  bytea: blind index HMAC-SHA256 (32 bytes) de telefone/JID/ID de
--                 conversa. O valor real nunca é gravado fora de *_enc.
--   device smallint: número do aparelho no endereço Signal (não é PII).
-- Toda tabela: tenant_id + instance_id, FK composta para core.instances e RLS
-- FORCE (ADR-0006).

-- +goose Up
CREATE SCHEMA wa;

-- Chave de dados (DEK) da instância, cifrada pela chave mestra do KMS.
CREATE TABLE wa.instance_keys (
  instance_id    uuid PRIMARY KEY,
  tenant_id      uuid NOT NULL,
  master_key_ref text NOT NULL,
  wrapped_dek    bytea NOT NULL,
  created_at     timestamptz NOT NULL DEFAULT now(),
  rewrapped_at   timestamptz,
  FOREIGN KEY (instance_id, tenant_id) REFERENCES core.instances (id, tenant_id) ON DELETE CASCADE
);

-- Dono atual da instância (fencing, ADR-0005/0010). Escrita no store exige
-- fence igual ao daqui; troca de dono só aumenta o valor.
CREATE TABLE wa.instance_owner (
  instance_id uuid PRIMARY KEY,
  tenant_id   uuid NOT NULL,
  fence       bigint NOT NULL CHECK (fence > 0),
  owner       text NOT NULL,
  updated_at  timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (instance_id, tenant_id) REFERENCES core.instances (id, tenant_id) ON DELETE CASCADE
);

-- Device inteira (chaves do número, JID, conta) num único blob cifrado.
CREATE TABLE wa.devices (
  instance_id uuid PRIMARY KEY,
  tenant_id   uuid NOT NULL,
  device_enc  bytea NOT NULL,
  updated_at  timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (instance_id, tenant_id) REFERENCES core.instances (id, tenant_id) ON DELETE CASCADE
);

CREATE TABLE wa.identity_keys (
  instance_id  uuid NOT NULL,
  tenant_id    uuid NOT NULL,
  user_idx     bytea NOT NULL CHECK (length(user_idx) = 32),
  device       integer NOT NULL CHECK (device >= 0),
  identity_enc bytea NOT NULL,
  PRIMARY KEY (instance_id, user_idx, device),
  FOREIGN KEY (instance_id, tenant_id) REFERENCES core.instances (id, tenant_id) ON DELETE CASCADE
);

CREATE TABLE wa.sessions (
  instance_id uuid NOT NULL,
  tenant_id   uuid NOT NULL,
  user_idx    bytea NOT NULL CHECK (length(user_idx) = 32),
  device      integer NOT NULL CHECK (device >= 0),
  session_enc bytea,
  PRIMARY KEY (instance_id, user_idx, device),
  FOREIGN KEY (instance_id, tenant_id) REFERENCES core.instances (id, tenant_id) ON DELETE CASCADE
);

CREATE TABLE wa.pre_keys (
  instance_id uuid NOT NULL,
  tenant_id   uuid NOT NULL,
  key_id      integer NOT NULL CHECK (key_id >= 0 AND key_id < 16777216),
  key_enc     bytea NOT NULL,
  uploaded    boolean NOT NULL,
  PRIMARY KEY (instance_id, key_id),
  FOREIGN KEY (instance_id, tenant_id) REFERENCES core.instances (id, tenant_id) ON DELETE CASCADE
);

CREATE TABLE wa.sender_keys (
  instance_id     uuid NOT NULL,
  tenant_id       uuid NOT NULL,
  chat_idx        bytea NOT NULL CHECK (length(chat_idx) = 32),
  sender_user_idx bytea NOT NULL CHECK (length(sender_user_idx) = 32),
  sender_device   integer NOT NULL CHECK (sender_device >= 0),
  sender_key_enc  bytea NOT NULL,
  PRIMARY KEY (instance_id, chat_idx, sender_user_idx, sender_device),
  FOREIGN KEY (instance_id, tenant_id) REFERENCES core.instances (id, tenant_id) ON DELETE CASCADE
);
CREATE INDEX sender_keys_sender_idx ON wa.sender_keys (instance_id, sender_user_idx);

-- key_id é aleatório (não é PII); key_data e fingerprint vão cifrados.
CREATE TABLE wa.app_state_sync_keys (
  instance_id uuid NOT NULL,
  tenant_id   uuid NOT NULL,
  key_id      bytea NOT NULL,
  key_enc     bytea NOT NULL,
  ts          bigint NOT NULL,
  PRIMARY KEY (instance_id, key_id),
  FOREIGN KEY (instance_id, tenant_id) REFERENCES core.instances (id, tenant_id) ON DELETE CASCADE
);

-- Versões e MACs de app state são hashes/MACs, não segredo nem PII.
CREATE TABLE wa.app_state_version (
  instance_id uuid NOT NULL,
  tenant_id   uuid NOT NULL,
  name        text NOT NULL,
  version     bigint NOT NULL,
  hash        bytea NOT NULL CHECK (length(hash) = 128),
  PRIMARY KEY (instance_id, name),
  FOREIGN KEY (instance_id, tenant_id) REFERENCES core.instances (id, tenant_id) ON DELETE CASCADE
);

CREATE TABLE wa.app_state_mutation_macs (
  instance_id uuid NOT NULL,
  tenant_id   uuid NOT NULL,
  name        text NOT NULL,
  version     bigint NOT NULL,
  index_mac   bytea NOT NULL CHECK (length(index_mac) = 32),
  value_mac   bytea NOT NULL CHECK (length(value_mac) = 32),
  PRIMARY KEY (instance_id, name, version, index_mac),
  FOREIGN KEY (instance_id, name) REFERENCES wa.app_state_version (instance_id, name) ON DELETE CASCADE,
  FOREIGN KEY (instance_id, tenant_id) REFERENCES core.instances (id, tenant_id) ON DELETE CASCADE
);

-- Nomes e telefone mascarado são PII: tudo dentro de contact_enc (inclui o JID,
-- para GetAllContacts).
CREATE TABLE wa.contacts (
  instance_id uuid NOT NULL,
  tenant_id   uuid NOT NULL,
  jid_idx     bytea NOT NULL CHECK (length(jid_idx) = 32),
  contact_enc bytea NOT NULL,
  PRIMARY KEY (instance_id, jid_idx),
  FOREIGN KEY (instance_id, tenant_id) REFERENCES core.instances (id, tenant_id) ON DELETE CASCADE
);

CREATE TABLE wa.chat_settings (
  instance_id         uuid NOT NULL,
  tenant_id           uuid NOT NULL,
  chat_idx            bytea NOT NULL CHECK (length(chat_idx) = 32),
  muted_until         bigint NOT NULL DEFAULT 0,
  pinned              boolean NOT NULL DEFAULT false,
  archived            boolean NOT NULL DEFAULT false,
  wasa_root_secret_id text NOT NULL DEFAULT '',
  PRIMARY KEY (instance_id, chat_idx),
  FOREIGN KEY (instance_id, tenant_id) REFERENCES core.instances (id, tenant_id) ON DELETE CASCADE
);

CREATE TABLE wa.message_secrets (
  instance_id uuid NOT NULL,
  tenant_id   uuid NOT NULL,
  chat_idx    bytea NOT NULL CHECK (length(chat_idx) = 32),
  sender_idx  bytea NOT NULL CHECK (length(sender_idx) = 32),
  message_id  text NOT NULL,
  secret_enc  bytea NOT NULL,
  PRIMARY KEY (instance_id, chat_idx, sender_idx, message_id),
  FOREIGN KEY (instance_id, tenant_id) REFERENCES core.instances (id, tenant_id) ON DELETE CASCADE
);
CREATE INDEX message_secrets_msg_idx ON wa.message_secrets (instance_id, message_id);

CREATE TABLE wa.privacy_tokens (
  instance_id      uuid NOT NULL,
  tenant_id        uuid NOT NULL,
  their_idx        bytea NOT NULL CHECK (length(their_idx) = 32),
  token_enc        bytea NOT NULL,
  ts               bigint NOT NULL,
  sender_ts        bigint,
  PRIMARY KEY (instance_id, their_idx),
  FOREIGN KEY (instance_id, tenant_id) REFERENCES core.instances (id, tenant_id) ON DELETE CASCADE
);
CREATE INDEX privacy_tokens_ts_idx ON wa.privacy_tokens (instance_id, ts);

CREATE TABLE wa.nct_salt (
  instance_id uuid PRIMARY KEY,
  tenant_id   uuid NOT NULL,
  salt_enc    bytea NOT NULL,
  FOREIGN KEY (instance_id, tenant_id) REFERENCES core.instances (id, tenant_id) ON DELETE CASCADE
);

-- Mapa LID <-> telefone POR INSTÂNCIA (no whatsmeow é global; aqui seria
-- vazamento entre tenants). Os dois lados só como blind index + blob cifrado.
CREATE TABLE wa.lid_map (
  instance_id uuid NOT NULL,
  tenant_id   uuid NOT NULL,
  lid_idx     bytea NOT NULL CHECK (length(lid_idx) = 32),
  pn_idx      bytea NOT NULL CHECK (length(pn_idx) = 32),
  mapping_enc bytea NOT NULL,
  PRIMARY KEY (instance_id, lid_idx),
  UNIQUE (instance_id, pn_idx),
  FOREIGN KEY (instance_id, tenant_id) REFERENCES core.instances (id, tenant_id) ON DELETE CASCADE
);

-- Mensagens recebidas já decifradas, até serem processadas (máx. 14 dias).
CREATE TABLE wa.event_buffer (
  instance_id     uuid NOT NULL,
  tenant_id       uuid NOT NULL,
  ciphertext_hash bytea NOT NULL CHECK (length(ciphertext_hash) = 32),
  plaintext_enc   bytea,
  server_ts       bigint NOT NULL,
  insert_ts_ms    bigint NOT NULL,
  PRIMARY KEY (instance_id, ciphertext_hash),
  FOREIGN KEY (instance_id, tenant_id) REFERENCES core.instances (id, tenant_id) ON DELETE CASCADE
);
CREATE INDEX event_buffer_insert_idx ON wa.event_buffer (instance_id, insert_ts_ms);

-- Mensagens enviadas guardadas para reenvio (máx. 7 dias).
CREATE TABLE wa.retry_buffer (
  instance_id   uuid NOT NULL,
  tenant_id     uuid NOT NULL,
  chat_idx      bytea NOT NULL CHECK (length(chat_idx) = 32),
  message_id    text NOT NULL,
  format        text NOT NULL,
  plaintext_enc bytea NOT NULL,
  ts_ms         bigint NOT NULL,
  PRIMARY KEY (instance_id, chat_idx, message_id),
  FOREIGN KEY (instance_id, tenant_id) REFERENCES core.instances (id, tenant_id) ON DELETE CASCADE
);
CREATE INDEX retry_buffer_ts_idx ON wa.retry_buffer (instance_id, ts_ms);

-- RLS FORCE em todas as tabelas do schema.
-- +goose StatementBegin
DO $$
DECLARE t text;
BEGIN
  FOR t IN SELECT tablename FROM pg_tables WHERE schemaname = 'wa' LOOP
    EXECUTE format('ALTER TABLE wa.%I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE wa.%I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON wa.%I USING (tenant_id = core.current_tenant()) WITH CHECK (tenant_id = core.current_tenant())',
      t);
  END LOOP;
END
$$;
-- +goose StatementEnd

GRANT USAGE ON SCHEMA wa TO app_rw;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA wa TO app_rw;

-- +goose Down
DROP SCHEMA wa CASCADE;
