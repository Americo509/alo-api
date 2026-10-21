# ADR-0010: Store próprio, cifrado e multi-tenant para o estado da sessão

**Status:** Proposto — aguardando aprovação (passo 1.3 da Fase 1)
**Data:** 2026-10-20
**Decisores:** Gustavo

## Contexto

O whatsmeow persiste o estado da sessão por interfaces definidas em
`store/store.go` e traz uma implementação SQL em `store/sqlstore/`. Análise
feita em `go.mau.fi/whatsmeow@v0.0.0-20261017175727-b2b1e71d45e2`:

### Interfaces que precisam de implementação (`store/store.go`)

`AllSessionSpecificStores` (linhas 195–208) agrega 12 interfaces: identidades,
sessões Signal, pre-keys, sender keys, chaves de sincronização de app state,
versões e MACs de app state, contatos, configurações de conversa, segredos de
mensagem, privacy tokens, salt NCT e buffer de eventos. `AllGlobalStores`
(linhas 210–212) tem o `LIDStore`. A `Device` (linhas 219–257) guarda as
chaves de identidade do número (`NoiseKey`, `IdentityKey`, `SignedPreKey`,
`AdvSecretKey`) e aponta para uma implementação de cada interface; o
`DeviceContainer` (linhas 123–126) persiste a `Device`.

### O que o `sqlstore` faz hoje

- **Tudo em texto claro.** O esquema (`sqlstore/upgrades/00-latest-schema.sql`)
  guarda em `bytea` sem cifragem: chaves do aparelho em `whatsmeow_device`,
  `whatsmeow_identity_keys`, `whatsmeow_pre_keys`, `whatsmeow_sessions`,
  `whatsmeow_sender_keys`, `whatsmeow_app_state_sync_keys`,
  `whatsmeow_message_secrets`, `whatsmeow_privacy_tokens`, `whatsmeow_nct_salt`.
- **Conteúdo de mensagem em claro.** `whatsmeow_event_buffer.plaintext` guarda a
  mensagem recebida já decifrada (`PutBufferedEvent`, `store.go` ~1076) até ser
  processada; `whatsmeow_retry_buffer.plaintext` guarda mensagens enviadas para
  reenvio (`AddOutgoingEvent`, ~1118). Registros antigos são apagados após 14
  dias (`DeleteOldBufferedHashes`, ~1091).
- **PII em claro e consultada por prefixo.** Endereços de contato (número de
  telefone + aparelho) são chave de busca, inclusive com `LIKE 'telefone:%'`
  (`deleteAllIdentitiesQuery`, `deleteAllSessionsQuery`, linhas 77–143).
- **Sem noção de tenant.** Tudo é chaveado por `our_jid`; não há `tenant_id`
  nem RLS. O `whatsmeow_lid_map` é **global**, compartilhado por todas as
  sessões do banco.
- **Colunas com restrição de tamanho** (`CHECK (length(key) = 32)` em pre-keys
  e identidades) e a `Device` gravada por SQL direto em `PutDevice`
  (`container.go`, linhas 191–255). Não dá para cifrar "por fora" sem mudar o
  código dele.
- Transações passadas pelo `context` (`DoDecryptionTxn`, ~1081, usando
  `dbutil.DoTxn`) e trava de processo para pre-keys (`preKeyLock`, ~343).

Tamanho: ~1.660 linhas (`store.go`, `container.go`, `lidmap.go`).

## Requisitos que o store precisa cumprir

1. Auth state cifrado em repouso com a DEK da instância (ADR da Fase 0, requisito
   de segurança; passo 1.2).
2. `tenant_id` + RLS em toda tabela (ADR-0006).
3. Escrita recusada para worker que perdeu a posse (fencing, ADR-0005).
4. Não guardar conteúdo de mensagem nem telefone em claro (LGPD, CONVENCOES).

## Opções consideradas

### A: usar o `sqlstore` como está
Falha nos requisitos 1, 2, 3 e 4.

### B: `sqlstore` + cifragem do disco / pgcrypto
Cifragem de disco não protege contra dump ou acesso SQL. pgcrypto exige mandar
a chave na query (vai para logs do Postgres). Falha nos requisitos 1 (na
prática), 2 e 3.

### C: fork do `sqlstore` com cifragem
Os arquivos modificados ficam sob MPL-2.0 (aceitável, não distribuímos), mas
viramos mantenedores de um fork que muda de esquema com frequência (14
migrations até hoje). A modelagem por `LIKE` em telefone teria de ser refeita
de qualquer jeito.

### D: implementação própria das interfaces (recomendada)
Escrever `internal/session/store` implementando `store.AllSessionSpecificStores`,
`store.LIDStore` e `store.DeviceContainer` sobre nosso esquema Postgres.

## Decisão (proposta): opção D

### Esquema

- Schema Postgres `wa` com uma tabela por interface. Toda tabela tem
  `tenant_id`, `instance_id`, RLS `FORCE` (ADR-0006).
- **Valores secretos** (chaves, sessões, segredos, plaintext de buffers, nomes
  de contato) vão em colunas `bytea` cifradas com a DEK da instância
  (`envelope.DataKey.Seal`). AAD = `instance_id | tabela | coluna | chave
  lógica`, para que um blob não possa ser copiado para outra linha.
- **Identificadores de contato** (número de telefone/LID) **não ficam em
  claro.** Para busca, um *blind index*: `HMAC-SHA256(k_idx, valor)`, com `k_idx`
  derivada da DEK por HKDF. Para endereço Signal `usuario:aparelho`, guardamos
  `user_idx = HMAC(usuario)`, o número do aparelho em claro (não é PII) e o
  usuário cifrado. Assim `DeleteAllSessions(telefone)` vira
  `WHERE user_idx = HMAC(telefone)`, sem `LIKE`, e `MigratePNToLID` atualiza
  `user_idx` e o valor cifrado.
- **`LIDStore` por instância**, não global. Compartilhar o mapa LID↔telefone
  entre tenants deixaria um cliente inferir dados observados pela instância de
  outro. Custo: dados duplicados entre instâncias; aceitável.

### Fencing

Tabela `wa.instance_owner(instance_id, fence)`. Toda escrita roda numa
transação que começa com
`SELECT 1 FROM wa.instance_owner WHERE instance_id=$1 AND fence=$2 FOR SHARE`;
sem linha, a transação aborta com `ErrFenced` e o worker desconecta. A troca de
dono faz `UPDATE ... SET fence=$novo WHERE fence < $novo`, que espera as escritas
em andamento terminarem. Transações aninhadas (`DoDecryptionTxn`) reaproveitam a
transação do `context`.

### Retenção e LGPD

- `event_buffer` e `retry_buffer`: plaintext cifrado; o `ClearBufferedEventPlaintext`
  apaga o valor de fato; job de limpeza respeita os 14 dias do protocolo.
- Exclusão da instância apaga todas as linhas e **destrói a DEK** (*crypto-shredding*):
  backups antigos ficam ilegíveis.

### Garantia de comportamento igual ao original

**Teste diferencial:** uma suíte de contrato roda a mesma sequência de operações
contra o `sqlstore` original (como referência, só em teste, num Postgres de
teste) e contra o nosso store, e compara os resultados. Cobre os casos sutis
(pre-keys não enviadas, migração PN→LID, transação de decifragem, contatos).
Um upgrade do whatsmeow que mude o comportamento quebra esse teste antes de
chegar em produção.

## Consequências

- Mais código nosso (~1.500–2.000 linhas + testes) em troca de cumprir os quatro
  requisitos. É o maior passo da Fase 1.
- Toda atualização do whatsmeow que adicionar método às interfaces quebra a
  compilação (bom: obriga a implementar) e entra no runbook de upgrade.
- Custo extra por escrita (checagem de fencing + cifragem): pequeno perto da
  latência de rede do WhatsApp; medido no teste de 72h.
- O `sqlstore` entra no `go.mod` só como dependência de teste do worker.

## Itens de ação (após aprovação)

1. [ ] Migrations do schema `wa` com RLS e teste de catálogo (ADR-0006).
2. [ ] Derivação de chaves (DEK → chave de cifragem por coluna + `k_idx`) com HKDF.
3. [ ] Implementação por interface, cada uma com teste unitário e diferencial.
4. [ ] Fencing com teste de integração de dois donos disputando a instância.
