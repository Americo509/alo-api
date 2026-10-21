# Diferenciais de produto

**Status:** Aprovado pelo PO (Q22 e Q23, 2026-10-20). Itens 10 a 15 vieram do
[benchmark](BENCHMARK.md).
**Data:** 2026-10-20

## Referência: o que a Z-API mostra publicamente

Lido em z-api.io e developer.z-api.io em 2026-10-20. Isto é o que **as páginas
públicas mencionam**; ausência na página não prova que o recurso não exista.

- Mencionado: API REST, webhooks em tempo real, fila de envio com retry, mídia
  até 100 MB, multiatendente no mesmo número, "chatbot integrado", nós para
  n8n/Make/Zapier, Postman/Swagger/SDKs, alerta de instância caída, painel,
  plano Partner com API de gestão de instâncias.
- Preço: R$ 99,99/mês por instância (Ultimate); R$ 89,99 a partir de 10
  instâncias (Partner); teste de 2 dias.
- **Não mencionado:** API oficial da Meta como produto, modo sandbox, MFA/SSO,
  log de auditoria, recursos de IA, log ou reenvio de webhooks, versionamento
  de API, idempotência.

## Tese

A Z-API vende **conexão**: um número ligado a uma API. O diferencial aqui é
vender **confiabilidade, conformidade e experiência de desenvolvedor**, no nível
que Stripe e Twilio estabeleceram, para um público que a Z-API atende mal:
quem integra sistemas sérios e quem atua em setor regulado (saúde, B2G).

## Catálogo

Fase = onde entra no roadmap proposto. ★ = proposta para o lançamento.

### 1. Canal duplo com failover transparente ★ (Fases 1–4)
Mesma API para canal oficial e não-oficial; roteamento por política e failover
automático para o oficial (ADR-0001). O painel mostra **por que** cada mensagem
foi por um canal ou outro.

### 2. Experiência de desenvolvedor estilo Stripe ★ (Fase 2b)
- **Modo sandbox:** chaves `test_` e um **simulador de WhatsApp** com contatos
  falsos que recebem, leem e respondem. O cliente integra sem número real e sem
  risco. O mesmo simulador serve de dublê nos nossos testes de integração e e2e.
- **`Idempotency-Key`** em todo POST: retry do cliente nunca duplica mensagem.
- **Versionamento por data** (`API-Version: 2026-10-20`): mudança nunca quebra
  integração existente.
- **Log de requisições** no painel: cada chamada à API, com PII mascarada.
- **Webhooks:** histórico de entregas, reenvio com um clique, verificador de
  assinatura e uma **CLI** que encaminha webhooks para `localhost` durante o
  desenvolvimento.
- **SDKs gerados do OpenAPI** (TypeScript, Python, PHP, Go) e documentação com
  exemplos executáveis.

### 3. Central de conformidade LGPD ★ (Fases 2b e 3)
- **Prova de opt-in por contato:** quando, por onde e com qual texto o contato
  consentiu. Exportável em caso de questionamento.
- "SAIR" honrado com registro; lista de supressão por tenant.
- Retenção configurável por tipo de dado; exportação e exclusão por titular.
- **Log de auditoria navegável** no painel: quem fez o quê, quando, de onde.
- Relatório pronto para DPO/encarregado de dados.

### 4. Rastreamento ponta a ponta de cada mensagem (Fases 2b e 6)
Linha do tempo por mensagem: recebida pela API → decisão de política (com o
motivo) → fila → enviada → entregue → lida → resposta. Busca por ID externo do
cliente. Usa o mesmo trace OpenTelemetry da observabilidade interna.

### 5. Saúde do número em tempo real (Fases 3 e 6)
Health score, histórico, alertas configuráveis (e-mail, webhook), explicação do
que puxou o score para baixo e o que fazer.

### 6. Segurança de nível enterprise (Fase 2a em diante)
Passkeys e MFA, sessões ativas, API keys com escopo e **lista de IPs
permitidos**, rotação de chave sem indisponibilidade, log de auditoria. Depois:
SSO (SAML/OIDC) para clientes corporativos.

### 7. Inbox multiatendente com copiloto de IA (Fase 5)
Atendimento humano com sugestão de resposta, resumo de conversa, classificação
de intenção e encaminhamento, sempre com aprovação humana em ação sensível e
sem orientação clínica.

### 8. Transparência operacional (Fase 6)
Página de status pública, histórico de incidentes, SLA por plano no canal oficial.

### 9. Acabamento de produto (contínuo)
Atualização em tempo real, paleta de comandos (Ctrl/⌘+K), atalhos de teclado,
modo escuro, acessibilidade WCAG 2.2 AA.

### 10. Coexistência como onboarding padrão ★ (Fase 4, proposto)
Cliente conecta o número que já usa no app WhatsApp Business ao canal oficial
sem perder o app (Embedded Signup V4). Mensagens enviadas pelo celular chegam
como eco na plataforma. O não-oficial fica como alternativa para quem não for
elegível. Ver BENCHMARK, seção 1.

### 11. WhatsApp Flows e Pix na conversa (Fases 4 e 5, proposto)
Formulários nativos (agendamento, confirmação de plantão) e cobrança com Pix
dinâmico pelo canal oficial. Construtor de Flow no painel com prévia.

### 12. Destinos de eventos (Fase 2b, proposto)
Além de webhook: fila do cliente (SQS, RabbitMQ, Kafka) e stream em tempo real
(WebSocket/SSE), saindo do mesmo outbox. Webhooks no padrão aberto **Standard
Webhooks**, com portal para o cliente gerenciar endpoints, ver tentativas e
reenviar.

### 13. Inbox completa (Fase 5, proposto — amplia o item 7)
Roteamento por regra, SLA com escalonamento, notas privadas e menções, CSAT,
relatórios. IA como agente autônomo com base de conhecimento, como copiloto do
atendente e como porta para o cliente plugar a própria IA.

### 14. Construtor visual de automações (Fase 5+, proposto)
Fluxos desenhados no painel, versionados, testáveis no sandbox, com
publicação controlada.

### 15. Ecossistema e revenda (Fase 6+, proposto)
Nós oficiais para n8n, Make e Zapier; integração com Chatwoot e Typebot; plano
parceiro white-label com painel multi-cliente e cobrança centralizada.

## Recomendação para o lançamento

Três diferenciais, porque se reforçam e atacam um público que a Z-API não
prioriza:

1. **Canal duplo** — é o que permite atender saúde e B2G.
2. **DX estilo Stripe com sandbox** — reduz o tempo de integração de quem paga.
   O simulador também acelera o nosso próprio desenvolvimento e testes.
3. **Central de conformidade LGPD** — argumento de venda para quem tem DPO,
   auditoria ou contrato público.

Os demais entram nas fases indicadas.
