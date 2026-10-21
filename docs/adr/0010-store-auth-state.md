# ADR-0010: Store próprio, cifrado e multi-tenant para o estado da sessão

**Status:** Aceito pelo PO em 2026-10-20, com a diretriz de seguir as boas
práticas de ISO e NIST (ver seção "Conformidade com ISO/IEC 27001 e NIST")
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

## Conformidade com ISO/IEC 27001 e NIST

Como cada prática se traduz em decisão de implementação. Referências: ISO/IEC
27001:2022 Anexo A e ISO/IEC 27701 (privacidade); publicações do NIST citadas.

| Prática | Referência | Implementação |
|---|---|---|
| Uso de criptografia definido por política | ISO 27001 A.8.24 | Este ADR + ADR-0005; algoritmos fixados em código, formato versionado para troca futura (agilidade criptográfica) |
| Algoritmo aprovado para cifragem autenticada | NIST SP 800-38D (GCM), FIPS 197 (AES) | AES-256-GCM, nonce de 96 bits aleatório, limite de 2^32 cifragens por chave documentado |
| Uma chave, um propósito | NIST SP 800-57 Parte 1, §5.2 | A DEK nunca é usada direto: chaves derivadas separadas para cifragem e para blind index |
| Derivação de chave aprovada | NIST SP 800-56C rev. 2 (HKDF), FIPS 198-1 (HMAC) | HKDF-SHA256 com rótulos de contexto distintos; blind index com HMAC-SHA256 |
| Hierarquia de chaves e proteção da chave mestra | NIST SP 800-57 Parte 1, §6 | Chave mestra no Vault Transit (não exportável); DEK cifrada por instância; rotação + rewrap |
| Mascaramento de dados pessoais | ISO 27001 A.8.11, ISO 27701 | Telefones e IDs de conversa só como blind index; nomes e conteúdo só cifrados |
| Exclusão de informação e sanitização | ISO 27001 A.8.10, NIST SP 800-88 rev. 1 (crypto erase) | Exclusão da instância destrói a DEK: dados e backups ficam ilegíveis |
| Separação de ambientes e de clientes | ISO 27001 A.8.3 (restrição de acesso) | RLS por tenant + mapa LID por instância |
| Integridade e anti-replay de dados armazenados | NIST SP 800-38D (AAD) | AAD amarra cada blob a instância, tabela e chave lógica |
| Registro de eventos sem dado sensível | ISO 27001 A.8.15 | Erros e logs nunca carregam chave, plaintext nem telefone |
| Módulo criptográfico validado | FIPS 140-3 | Só a biblioteca padrão do Go (`crypto/*`), cujo módulo criptográfico foi feito para FIPS 140-3 e tem modo `GODEBUG=fips140=on`. Conferir o status do certificado CMVP vigente antes de prometer FIPS em contrato |

## Consequências

- Mais código nosso (~1.500–2.000 linhas + testes) em troca de cumprir os quatro
  requisitos. É o maior passo da Fase 1.
- Toda atualização do whatsmeow que adicionar método às interfaces quebra a
  compilação (bom: obriga a implementar) e entra no runbook de upgrade.
- Custo extra por escrita (checagem de fencing + cifragem): pequeno perto da
  latência de rede do WhatsApp; medido no teste de 72h.
- O `sqlstore` entra no `go.mod` só como dependência de teste do worker.

## Itens de ação

1. [x] Migrations do schema `wa` com RLS e teste de catálogo (ADR-0006).
2. [x] Derivação de chaves (DEK → chave de cifragem + chave de blind index) com HKDF.
3. [x] Implementação de todas as interfaces, com teste diferencial contra o
   `sqlstore` (`internal/session/store/diff_integration_test.go`).
4. [x] Fencing com teste de integração de dois donos disputando a instância.
5. [ ] Rotação periódica da DEK (re-cifrar o estado) e destruição da DEK na
   exclusão da instância (crypto-shredding): Fase 2, junto com o ciclo de vida
   da instância no control plane.

### Diferenças intencionais em relação ao `sqlstore`

- Busca por usuário é igualdade exata no blind index. O `sqlstore` usa
  `LIKE 'usuario:%'`, em que `_` no nome do usuário vira curinga.
- `DeleteOldBufferedHashes` apaga só os eventos da própria instância (o
  `sqlstore` apaga de todas as devices do banco).
- Registration ID gerado com `crypto/rand` (o `sqlstore` usa `math/rand`).
- Retenções usam o relógio injetado (testável), não `time.Now`.
