# ADR-0006: Isolamento por tenant com Row Level Security

**Status:** Proposto
**Data:** 2026-10-20
**Decisores:** Gustavo

## Contexto

Requisito: `tenant_id` em toda tabela + RLS, com teste provando que o tenant A
não lê dados do B. RLS mal configurado falha aberto de formas silenciosas:
role dona da tabela ignora a política, role com `BYPASSRLS` ignora tudo, e
variável de sessão vaza entre requisições quando a conexão volta ao pool.

## Decisão

1. **Três roles no Postgres:**
   - `app_owner`: dono das tabelas, usado só por `cmd/migrate`. Nunca pela aplicação.
   - `app_rw`: usado pelos serviços. Sem `BYPASSRLS`, não é dono de nada.
   - `app_ops`: leitura administrativa com auditoria, uso manual e raro.
2. Toda tabela com dado de tenant: `ENABLE` **e** `FORCE ROW LEVEL SECURITY`,
   política `USING (tenant_id = current_setting('app.tenant_id')::uuid)` e
   `WITH CHECK` igual.
3. **Tenant setado por transação, nunca por sessão:** `SET LOCAL app.tenant_id`
   (via `set_config(..., true)`) dentro da transação. Assim o valor some no
   commit/rollback e não vaza pelo pool.
4. Acesso ao banco só por `tenant.WithTx(ctx, pool, tenantID, fn)`. Repositórios
   não recebem `*pgxpool.Pool`, só a transação já com tenant. Lint proíbe
   `pool.Query` fora desse pacote.
5. `current_setting` sem valor → erro (sem o parâmetro `missing_ok`), então
   query sem tenant falha em vez de retornar vazio.
6. **Testes automatizados:**
   - Tenant A insere; tenant B não lê, não atualiza, não apaga.
   - Teste de catálogo: toda tabela em `public` com coluna `tenant_id` tem RLS
     `FORCE` e política — falha o CI se alguém criar tabela sem.
   - Conexão reutilizada do pool após transação de A não carrega tenant de A.

## Consequências

- Tabelas globais (ex.: catálogo de templates da Meta, se houver) ficam em schema
  separado, explícito.
- Jobs que varrem todos os tenants (retenção, partições) rodam iterando tenant
  por tenant, ou com role específica auditada — decidir caso a caso em ADR.
- Pequeno custo por query da política; aceitável.
