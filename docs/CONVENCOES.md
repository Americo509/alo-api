# Convenções

## Código

- `context.Context` é o primeiro parâmetro de toda função que faz I/O.
- Erros: `fmt.Errorf("contexto: %w", err)`; erros de domínio como variáveis
  sentinela em `internal/domain` (`ErrSemConsentimento`, `ErrInstanciaDegradada`…).
  A borda HTTP traduz para respostas no formato RFC 9457 (problem+json).
- **Tempo nunca vem de `time.Now()` direto** em lógica de negócio: recebe
  `clock.Clock`. Testes usam `clock.Fake` e avançam o tempo; nenhum `time.Sleep`
  em teste.
- Aleatoriedade (jitter, delays) recebe uma fonte injetável, semeável em teste.
- Configuração por struct tipada carregada no início; nada de ler env no meio do
  código. Segredos vêm de `crypto.SecretSource` (Vault/KMS), nunca de env em produção.
- IDs: UUIDv7 (ordenáveis por tempo, bons para partição e índice).

## Logs, métricas e dados pessoais

- **Proibido logar** conteúdo de mensagem, número de telefone em claro, nome de
  contato, auth state, API key, segredo de webhook.
- Para correlacionar sem expor: `phone_ref = HMAC-SHA256(chave_de_log, e164)`
  truncado. A chave de log fica no Vault e é rotacionável.
- O handler de `slog` aplica redação por nome de atributo como rede de segurança;
  a regra principal continua sendo não passar o dado.
- Labels de métrica nunca têm número de telefone ou ID de contato
  (cardinalidade e PII). `instance_id` e `tenant_id` são permitidos.

## Testes

- Unitário ao lado do código (`_test.go`), sem rede, sem banco.
- Integração em `test/integration`, build tag `integration`, com testcontainers.
- `go test -race` sempre no CI.
- Dados de teste: números do bloco reservado a ficção ou gerados, nunca
  números reais; nenhum token real em fixture.

## Git

- Branch curta por passo, PR pequeno, Conventional Commits
  (`feat(session): ...`, `fix(policy): ...`).
- CI bloqueia merge se falhar: lint, testes, `govulncheck`, `go-licenses`, `gitleaks`.
- Toda mudança que contraria um ADR aceito vem com um ADR novo no mesmo PR.
