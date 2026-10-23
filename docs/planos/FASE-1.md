# Plano — Fase 1: Núcleo de sessão

**Status:** Aprovado pelo PO em 2026-10-20
**Data:** 2026-10-20

## Objetivo e critério de saída

Uma instância conecta (QR e pairing code), envia e recebe texto e mídia,
entrega o recebimento por webhook assinado e guarda o auth state cifrado.
**Saída:** 1 número estável por 72h, testes passando, README/ADRs atualizados.

## Fora do escopo (vem depois)

Multi-tenant real, painel, login, cobrança (Fase 2); motor de políticas
(Fase 3); Cloud API (Fase 4). Nesta fase existe **um tenant fixo de
desenvolvimento** e a API interna é protegida por uma chave de operador.

## Trava de segurança desta fase

Sem motor de políticas ainda, o envio só é permitido para uma **lista de
números de teste** configurada (allowlist). Qualquer outro destino é recusado.
Isso protege o número de teste e impede envio acidental.

## Passos (cada um é um PR pequeno com testes)

| # | Passo | Entrega verificável |
|---|---|---|
| 1.0 | Esqueleto do repositório | `go.mod`, `Makefile`, `deploy/compose` (Postgres, Redis, NATS, MinIO, Vault dev), CI com lint, `-race`, `govulncheck`, `go-licenses`, `gitleaks`, `depguard`. CI verde num repositório vazio |
| 1.1 | Domínio da instância | Máquina de estados `DESCONECTADA → PAREANDO → CONECTADA → DEGRADADA → BANIDA` como função pura; teste de tabela cobrindo todas as transições válidas e inválidas |
| 1.2 | Cifragem de envelope | `crypto.KeyManager` (interface) + adapter Vault Transit + fake para teste. AES-256-GCM com chave de dados por instância e dado associado (`instance_id`) para impedir troca de blob entre instâncias. Testes: ida e volta, adulteração detectada, rotação de chave mestra |
| 1.3 | **ADR-0010: store do auth state** | Leitura do `store/` e `store/sqlstore` do whatsmeow (com arquivos citados) para decidir: envolver o store SQL dele ou implementar as interfaces de store com cifragem e fencing. **Nada de código antes desse ADR aprovado** |
| 1.4 | Store implementado | Conforme o ADR-0010, com migrations, cifragem e fencing token; testes de integração com Postgres real |
| 1.5 | Lease + fencing | `session/lease` no Redis com relógio injetável (ADR-0005). Teste de integração de dois workers disputando a mesma instância com pausa simulada: só um grava |
| 1.6 | Pareamento | QR (novo código a cada ~20s, para após 3 tentativas sem leitura) e pairing code. A regra de "3 tentativas" testada com relógio falso. Verificar no `qrchan.go` como a biblioteca já emite e expira os códigos, para não duplicar lógica |
| 1.7 | Conexão e reconexão | Keep-alive fica com a biblioteca (em `keepalive.go`: intervalo sorteado entre 20 e 30s, prazo de resposta de 10s, reconexão após 3 min sem sucesso). Nossa camada só acrescenta backoff exponencial com teto e jitter entre tentativas de reconexão completas, e transição de estado + evento a cada mudança |
| 1.8 | Contrato worker ↔ API | Mensagens NATS em **Protobuf** com `buf` (checagem de quebra de contrato no CI). Subjects versionados (`v1.instance.<id>.send`, `v1.instance.<id>.inbound`…) |
| 1.9 | Envio e recebimento | Texto e mídia (mídia vem do MinIO por referência, nunca no corpo da mensagem NATS). Recebimento normalizado para `MensagemEntrada` e publicado no NATS |
| 1.10 | Webhook de recebimento | `webhook-dispatcher`: outbox no Postgres, assinatura **Standard Webhooks**, retry com backoff, DLQ. Testes: assinatura válida com biblioteca oficial de verificação, reenvio idempotente (`webhook-id` estável) |
| 1.11 | Observabilidade mínima | `slog` com redação de PII + ponte para o zerolog do whatsmeow; métricas por instância (estado, reconexões, falhas de keep-alive, envios, erros); traces OTel da API até o envio |
| 1.12 | Runbooks e teste de 72h | `runbooks/upgrade-whatsmeow.md` (inclui reler licenças do `go.mod`) e roteiro do teste de estabilidade de 72h com os painéis de métricas usados como evidência |

## Interfaces centrais (esboço)

```go
type KeyManager interface {
    WrapKey(ctx context.Context, plaintextDEK []byte) (wrapped []byte, keyVersion string, err error)
    UnwrapKey(ctx context.Context, wrapped []byte, keyVersion string) ([]byte, error)
}

type Lease interface {
    Acquire(ctx context.Context, instanceID uuid.UUID) (Fence, error)
    Renew(ctx context.Context, f Fence) error
    Release(ctx context.Context, f Fence) error
}

type Clock interface {
    Now() time.Time
    After(d time.Duration) <-chan time.Time
}
```

## Riscos

| Risco | Mitigação |
|---|---|
| Número de teste ser restrito durante a fase | Número dedicado e descartável (Q4); allowlist de destinos; volume mínimo |
| Store cifrado exigir reimplementar interfaces grandes do whatsmeow | ADR-0010 antes de codar; se o custo for alto, avaliar cifragem por coluna sobre o store existente |
| Mudança de protocolo durante a fase | Fixar versão do whatsmeow; runbook de upgrade |
| Fronteira GPL-3.0 (ADR-0003) | `depguard` desde o passo 1.0 |
| Mídia maliciosa recebida | Tamanho máximo, detecção de tipo pelo conteúdo (não pela extensão), armazenamento em bucket sem execução, URL pré-assinada curta |

## Pré-requisitos

1. **Pasta definitiva do projeto com Git.** Hoje os documentos estão numa pasta
   temporária desta sessão.
2. Q4 (número de teste) só é necessária no passo 1.6; até lá tudo roda com
   fakes e containers.
3. Q5 respondida (2026-10-23): module path `github.com/Americo509/alo-api`.
