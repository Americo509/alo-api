# Alô API — plataforma de mensageria WhatsApp

Gateway multi-tenant que expõe uma API REST única para os sistemas clientes
(CONECTA Plantão, sistema da nutricionista, automações) e entrega mensagens por
dois canais atrás de uma mesma porta: Cloud API oficial da Meta e engine
não-oficial sobre whatsmeow.

> **Status:** Fase 0 (decisões). Nenhum código de produção ainda.
>
> **Modelo comercial:** SaaS vendido a terceiros, com painel web para o cliente
> operar (Q1, 2026-10-20). A tecnologia do painel depende da Q9.

## Estrutura do repositório (proposta)

Monorepo Go com **um único módulo** (`go.mod` na raiz). Um módulo só evita
versionamento interno entre pacotes enquanto o time é pequeno; dá para separar
depois se um binário precisar de ciclo de release próprio.

```
.
├── cmd/                        # um diretório por binário; só main.go + wiring
│   ├── api/                    # control plane: REST pública (/v1) + BFF (/bff), roteador de canal
│   ├── session-worker/         # ÚNICO binário que importa whatsmeow (ver ADR-0003)
│   ├── webhook-dispatcher/     # lê outbox, assina HMAC, entrega, retry, DLQ
│   └── migrate/                # aplica migrations com role administrativa
│
├── internal/
│   ├── domain/                 # tipos e regras puras: Instance, Message, Contact,
│   │                           #   máquina de estados da instância. Sem I/O.
│   ├── channel/                # porta CanalDeMensagem + roteador por política
│   │   ├── cloudapi/           # adapter Cloud API (HTTP para a Meta)
│   │   └── unofficial/         # adapter que fala com session-worker via NATS
│   ├── session/                # (só session-worker) ciclo de vida, lease + fencing,
│   │   └── store/              #   store cifrado do auth state
│   ├── policy/                 # motor de políticas de envio (Fase 3)
│   ├── tenant/                 # contexto de tenant, RLS helpers
│   ├── apikey/                 # emissão, hash Argon2id, escopo, rotação
│   ├── identity/               # login OIDC, usuários, memberships, sessão (ADR-0007)
│   ├── billing/                # entitlement, planos, liberação manual (ADR-0008)
│   │   └── gateway/            # adapters de pagamento
│   ├── admin/                  # ações do admin da plataforma, sempre auditadas
│   ├── webhook/                # outbox, assinatura, verificação
│   ├── crypto/                 # envelope encryption; interface KeyManager (Vault/KMS)
│   ├── phone/                  # normalização E.164 (libphonenumber)
│   ├── queue/                  # abstração sobre NATS JetStream
│   ├── storage/
│   │   ├── postgres/           # repositórios (sqlc + pgx)
│   │   └── objects/            # S3/MinIO
│   ├── ai/                     # Fase 5
│   ├── audit/                  # audit_log append-only
│   ├── clock/                  # relógio injetável (testes sem sleep)
│   └── observability/          # OTel, métricas, logger com redação de PII
│
├── web/                        # SPA do painel (React + TS + Vite, pnpm) — ADR-0009
│   ├── src/
│   │   ├── api/                # cliente gerado do OpenAPI (não editar à mão)
│   │   ├── design-system/      # tokens e componentes sobre Radix
│   │   ├── features/           # uma pasta por área: auth, instances, inbox…
│   │   └── routes/             # TanStack Router
│   └── e2e/                    # Playwright contra o modo sandbox
│
├── api/openapi.yaml            # contrato da API pública (fonte da verdade)
├── api/bff.openapi.yaml        # contrato do BFF (só o painel usa)
├── migrations/                 # SQL versionado
├── deploy/
│   ├── compose/                # ambiente local: postgres, redis, nats, minio, vault-dev
│   └── docker/                 # Dockerfiles por binário
├── test/integration/           # testes com testcontainers (build tag `integration`)
├── docs/
│   ├── adr/                    # decisões de arquitetura
│   ├── threat-model/           # STRIDE (esboço na Fase 2, final na Fase 6)
│   ├── runbooks/               # incluindo upgrade do whatsmeow
│   ├── CONVENCOES.md
│   └── PERGUNTAS-ABERTAS.md
├── THIRD_PARTY_NOTICES.md      # gerado no CI (go-licenses)
└── Makefile
```

Regras de dependência entre pacotes (checadas no CI com `depguard`):

- `domain` não importa nada de `internal/`.
- Só `cmd/session-worker` e `internal/session/...` importam `go.mau.fi/whatsmeow`.
- `cmd/api` nunca importa `internal/session`.
- `channel/*` dependem da porta, nunca o contrário.

## Desenvolvimento local

Pré-requisitos: Go 1.27+ (a versão exata é baixada sozinha pelo `toolchain`
do `go.mod`) e Docker. Não precisa de `make`: as tarefas rodam pelo
[Task](https://taskfile.dev), fixado em `tools/go.mod`.

```bash
go tool -modfile=tools/go.mod task --list        # todas as tarefas
go tool -modfile=tools/go.mod task compose-up    # Postgres, Redis, NATS, S3, Vault
go tool -modfile=tools/go.mod task check         # formatação, lint, testes, vulnerabilidades, licenças
go tool -modfile=tools/go.mod task test-docker   # testes com -race em container (Windows sem gcc)
```

Portas locais (todas em `127.0.0.1`, ajustáveis por `DEV_*_PORT`):
Postgres 15432, Redis 16379, NATS 14222 (monitoramento 18222), S3 18333,
Vault 18200.

Ferramentas fixadas em `tools/go.mod` (módulo separado, para as dependências
delas não se misturarem com as do produto): Task, golangci-lint, govulncheck,
go-licenses, buf. O gitleaks roda em container.

## Documentos

- [ADRs](docs/adr/README.md)
- [Convenções](docs/CONVENCOES.md)
- [Perguntas abertas](docs/PERGUNTAS-ABERTAS.md)
- [Diferenciais de produto](docs/DIFERENCIAIS.md)
- [Benchmark de plataformas](docs/BENCHMARK.md)
- [Plano da Fase 1](docs/planos/FASE-1.md)
