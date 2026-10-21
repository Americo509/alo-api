# ADR-0008: Acesso condicionado a pagamento ou liberação manual

**Status:** Proposto — gateway de pagamento em aberto (PERGUNTAS-ABERTAS Q18)
**Data:** 2026-10-20
**Decisores:** Gustavo

## Contexto

O cliente se cadastra sozinho (login social, ADR-0007), mas só usa a plataforma
se **pagou** ou se **o admin da plataforma liberou manualmente**. Os dois caminhos
precisam convergir numa única checagem, aplicada em todo ponto de entrada.

## Decisão

### 1. Uma regra só: *entitlement*

```
acesso(tenant, agora) =
    assinatura ativa ou em carência
 OU liberação manual vigente (não revogada, valid_until nulo ou > agora)
```

O resultado traz também o **plano** (limites: nº de instâncias, mensagens/mês,
canais permitidos, IA). Se houver os dois, vale o plano mais generoso.

É uma função pura em `internal/billing/entitlement`, testada com relógio
injetável. Ninguém mais decide acesso.

### 2. Modelo de dados

- `plans`: código, nome, limites, preço de referência. Tabela global, editável
  só pelo admin da plataforma.
- `subscriptions`: tenant, plano, status, `provider`, `provider_ref`,
  `current_period_end`, `grace_until`.
- `access_grants` (liberação manual): tenant, plano, `granted_by`, motivo
  obrigatório, `valid_until` (nulo = sem prazo), `revoked_at`, `revoked_by`.
- `billing_events`: eventos recebidos do gateway, com ID do provedor para
  idempotência.

### 3. Estados da assinatura

`PENDENTE → ATIVA → INADIMPLENTE (carência) → SUSPENSA → CANCELADA`

- Carência configurável por plano. Durante a carência o tenant opera e vê aviso.
- **SUSPENSA bloqueia envio e o painel vira só leitura + tela de pagamento.**
  Webhooks de entrada continuam sendo recebidos e guardados até o fim do prazo
  de retenção, para o cliente não perder mensagens dos contatos dele.
- Suspensão nunca apaga dados. Exclusão segue a política de retenção (LGPD).

### 4. Pagamento por trás de uma porta

```go
type GatewayPagamento interface {
    CriarCheckout(ctx context.Context, tenant TenantID, plano PlanoID) (URLCheckout, error)
    CancelarAssinatura(ctx context.Context, ref string) error
    VerificarWebhook(r *http.Request) (EventoCobranca, error) // assinatura do provedor
}
```

- O status da assinatura **só muda por webhook verificado do gateway**, nunca
  pelo retorno do navegador após o checkout (que pode ser forjado).
- Webhook processado de forma idempotente (`billing_events.provider_event_id`
  único).
- Um adapter por gateway; o resto do sistema não sabe qual é.

### 5. Onde a regra é aplicada

| Ponto | Sem acesso |
|---|---|
| Painel | Redireciona para tela de planos/pagamento; configurações e dados em leitura |
| API pública | `402 Payment Required` com problem+json |
| Envio (worker/roteador) | Mensagem recusada antes de entrar na fila |
| Instâncias não-oficiais | Desconectadas de forma ordenada após a suspensão |

O resultado do entitlement fica em cache no Redis por pouco tempo e é
invalidado quando chega webhook do gateway ou quando o admin libera/revoga.

### 6. Admin da plataforma (você)

- Papel `platform_admin`, separado dos papéis de tenant, com MFA obrigatório.
- Ações: liberar acesso (com motivo e prazo), revogar, suspender tenant por abuso
  (ADR-0004), aprovar identificação para o canal não-oficial.
- Toda ação vai para o `audit_log`. O acesso a dados de tenants pelo admin usa
  role separada e auditada (ADR-0006), não desliga o RLS.

## Encaixe nas fases (divisão aprovada pelo PO em 2026-10-20)

- **Fase 2a:** identidade (ADR-0007).
- **Fase 2b:** tenants, papéis, API pública, entitlement com **liberação manual**
  e painel de admin. Isso já permite onboard dos primeiros clientes.
- **Fase 2c:** integração com gateway de pagamento, checkout e webhooks.
  Pré-requisito para abrir venda self-service.

## Consequências

- Liberação manual cobre piloto, cortesia e clientes que pagam por fora (boleto
  avulso, contrato).
- Mudar de gateway é trocar adapter, não reescrever regra de acesso.
- Revisitar: trial gratuito (seria só uma `access_grant` automática com prazo).
