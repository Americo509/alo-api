# ADR-0002: Stack tecnológica

**Status:** Proposto
**Data:** 2026-10-20
**Decisores:** Gustavo

## Contexto

Os componentes principais já foram decididos (Go, whatsmeow, PostgreSQL 16,
Redis 7, NATS JetStream, S3/MinIO, Vault/KMS, pgvector, OpenTelemetry +
Prometheus + Grafana + Loki, Docker). Falta fixar as bibliotecas e ferramentas
que definem as convenções do código.

## Decisão

Itens marcados com **(?)** estão em [PERGUNTAS-ABERTAS](../PERGUNTAS-ABERTAS.md).

| Área | Escolha proposta | Por quê |
|------|------------------|---------|
| Go | 1.26+ | O `go.mod` do whatsmeow declara `go 1.26.0` (lido em 2026-10-20) |
| HTTP | `net/http` da stdlib (roteamento com padrões, Go 1.22+) **(?)** | Sem dependência; middlewares próprios são poucos |
| Contrato | OpenAPI 3.1 em `api/openapi.yaml`, servidor gerado com `oapi-codegen` | Contrato como fonte da verdade, validação na borda |
| Postgres | `pgx/v5` + `sqlc` | SQL explícito (importante para RLS), tipos gerados |
| Migrations | `goose` **(?)** | SQL puro, simples; alternativa: Atlas |
| Particionamento | Partições mensais criadas por job próprio (ou `pg_partman` se o provedor oferecer) | Evitar extensão que o Postgres gerenciado pode não ter |
| Redis | `go-redis/v9` | Padrão |
| NATS | `nats.go` com JetStream | Streams por instância, `Nats-Msg-Id` para dedupe |
| Logger | `log/slog` com handler de redação; ponte para o zerolog do whatsmeow **(?)** | stdlib; um formato só no Loki |
| Telefone | `nyaruka/phonenumbers` (porta Go do libphonenumber) | Regra de DDD/nono dígito fora do nosso código |
| Hash de API key | `golang.org/x/crypto/argon2` (Argon2id) | Requisito |
| Testes | stdlib `testing` + `testcontainers-go` para integração | Postgres/Redis/NATS reais no CI |
| Qualidade/segurança no CI | `golangci-lint` (com `depguard`, `gosec`), `govulncheck`, `go-licenses`, `gitleaks` | Ver ADR-0003 para licenças |
| Deploy inicial | Docker Compose em VM **(?)** → Kubernetes quando houver mais de um worker | Não pagar complexidade de K8s na Fase 1 |

## Opções consideradas (principais divergências)

- **chi vs stdlib:** chi tem mais middlewares prontos; stdlib basta e evita
  dependência. Proposta: stdlib, reavaliar se o roteamento complicar.
- **sqlc vs GORM:** ORM esconde SQL e dificulta raciocinar sobre RLS e
  partições. sqlc mantém o SQL visível.
- **slog vs zerolog:** whatsmeow usa zerolog internamente. Proposta: slog na
  nossa base e um adaptador para os logs do whatsmeow passarem pelo mesmo
  filtro de redação.

## Consequências

- Toda query passa por SQL escrito à mão, revisável.
- O CI precisa de Docker para os testes de integração.
- Revisitar: K8s, Vault vs KMS gerenciado (depende de onde hospeda).

## Itens de ação

1. [ ] Responder as perguntas marcadas **(?)**.
2. [ ] `Makefile` com `lint`, `test`, `test-integration`, `licenses`, `vuln`.
3. [ ] `deploy/compose` com todos os serviços em modo dev.
