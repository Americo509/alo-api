# Fase 2b — Tenants, papéis, API pública e liberação manual

Pré-requisito: Fase 2a (identidade) fechada. Ordem das etapas (cada uma com
testes, lint e commit próprio):

| Passo | Entrega |
|---|---|
| 2b.1 | `authz` (matriz papel→permissão, puro) e `tenant` (criar, listar, membros, papéis, "nunca zero donos") |
| 2b.2 | Convites de membros por e-mail (token de uso único, expira, papel limitado ao do convidante) |
| 2b.3 | `billing/entitlement`: planos, liberações manuais, regra pura "acesso = assinatura OU liberação" |
| 2b.4 | `apikey`: emissão (mostrada uma vez), hash, escopos, expiração, rotação, revogação, último uso |
| 2b.5 | Admin da plataforma: liberar/revogar acesso, suspender tenant; MFA recente obrigatório; tudo auditado |
| 2b.6 | Rotas BFF de tenants/membros/chaves/admin e middleware da API pública (chave→tenant, 402, limite) |
| 2b.7 | `cmd/api`: raiz de composição que liga identidade, BFF e API |

Fora desta fase: gateway de pagamento (2c), webhooks de saída, front-end,
canal oficial (por último). Nada da camada de conexão do motor não oficial.

Decisões de projeto:
- Criar tenant não precisa de função privilegiada: a transação define
  `app.tenant_id` com o ID novo e a política RLS (`WITH CHECK`) passa.
- Autorização é sempre `Authorize(usuário, tenant, permissão)` — um único ponto.
- Invariante "todo tenant tem ao menos um dono" é garantida na transação
  (`FOR UPDATE`) e testada com concorrência.
