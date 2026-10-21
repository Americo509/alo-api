# Benchmark de plataformas

**Data da pesquisa:** 2026-10-20. Fontes no fim. Boa parte vem de páginas de
terceiros (templates de hospedagem, blogs de concorrentes); o que estiver
marcado como *a confirmar* precisa ser validado na documentação oficial antes
de virar requisito.

## Quem foi analisado

| Plataforma | Categoria | O que faz de melhor |
|---|---|---|
| **Z-API** | Gateway não-oficial (BR) | Simplicidade: número + API + webhook. Nós para n8n/Make/Zapier. Plano Partner para revendas |
| **Evolution API** | Gateway open source (Node) | Baileys **e** Cloud API no mesmo produto; eventos por webhook, RabbitMQ, Kafka, SQS e WebSocket; integrações nativas com Chatwoot, Typebot, Dify, OpenAI (áudio→texto), n8n |
| **WAHA** | Gateway open source | Vários engines plugáveis (navegador, WebSocket, Go); painel para sessões e QR; Swagger |
| **Twilio** | CPaaS global | DX de referência; **Event Streams** (eventos para webhook, Kinesis, Segment), eventos de ciclo de vida de template, Studio (fluxos visuais), SDKs de cliente |
| **Infobip / Gupshup** | CPaaS enterprise | Certificações (ISO, SOC 2) como argumento de venda; IA própria; multicanal |
| **Blip / Zenvia** | Plataformas BR de atendimento | Construtor de bots, atendimento híbrido IA + humano, CRM simples, campanhas com template; Zenvia junta WhatsApp, SMS e e-mail |
| **respond.io / Wati** | Inbox para negócios | Inbox omnichannel, agentes de IA com RAG para qualificar lead e agendar |
| **Chatwoot** | Inbox open source | Roteamento por idioma/plano/sentimento, SLA, notas privadas e menções, CSAT, agente de IA (Captain) + copiloto, framework para plugar bot externo |
| **Svix** | Infra de webhooks | Assinatura padronizada, rotação de segredo, retry com backoff, **portal para o cliente gerenciar endpoints**, reenvio |

## O que a pesquisa muda no projeto

### 1. Coexistência: API oficial sem perder o app (impacto alto)

A Meta permite que um número **já usado no app WhatsApp Business continue no
app e ao mesmo tempo opere pela Cloud API** ("coexistence"), via Embedded
Signup. A equipe segue conversando pelo celular e a automação roda pela API
oficial. Pontos levantados:

- Requer app Business 2.24.17+, admin do portfólio Meta, número não pessoal.
- Pode sincronizar até 6 meses de histórico.
- Mensagens enviadas manualmente no app chegam como evento `message.echo`.
- Elegibilidade depende de idade e qualidade da conta; cobertura por país varia
  (*a confirmar para o Brasil*).
- Um provedor informa que o Embedded Signup V2 sai de linha em outubro de 2026;
  integrar direto na **V4** (*a confirmar*).

**Por que importa:** o principal motivo de pequenas empresas usarem gateway
não-oficial é não querer perder o WhatsApp no celular. A coexistência resolve
isso no canal oficial. Proposta: **coexistência vira o caminho padrão de
onboarding**; o não-oficial continua disponível (decisão já tomada), como
alternativa para quem não é elegível.

### 2. WhatsApp Flows (formulários dentro do chat)

Telas nativas no WhatsApp (formulário, seleção de horário). Há categoria
`APPOINTMENT_BOOKING` e template de agendamento da Meta. Encaixa direto em:
- nutricionista: agendar e remarcar consulta;
- CONECTA: confirmar ou recusar plantão com um toque, com registro estruturado.

### 3. Pagamento Pix dentro da conversa

A Cloud API no Brasil tem pagamento nativo com **código Pix dinâmico** enviado na
conversa (via provedor). Encaixa em cobrança de consulta e mensalidade.
Combinação Flow + pagamento tem fontes conflitantes (*a confirmar*); o desenho
seguro é agendar no Flow e depois enviar a cobrança Pix.

### 4. Eventos além do webhook

Evolution entrega eventos em RabbitMQ, Kafka, SQS e WebSocket; Twilio tem Event
Streams. Proposta: **"destinos de eventos"** por tenant — webhook (padrão),
fila do cliente (SQS, RabbitMQ, Kafka) e stream em tempo real (WebSocket/SSE).
Tudo sai do mesmo outbox, com a mesma garantia de entrega.

### 5. Padrão aberto de webhook

Adotar a especificação **Standard Webhooks** (cabeçalhos `webhook-id`,
`webhook-timestamp`, `webhook-signature`; HMAC-SHA256 sobre
`id.timestamp.corpo`; segredo `whsec_…`; várias assinaturas durante rotação).
O cliente valida com bibliotecas oficiais prontas em várias linguagens, em vez
de copiar código de verificação da nossa documentação.

### 6. Inbox de verdade (Chatwoot, respond.io)

Roteamento por regra (idioma, plano, sentimento), SLA com escalonamento, notas
privadas e menções, CSAT, relatórios por canal. IA em três papéis: agente que
responde sozinho com base na base de conhecimento, copiloto que rascunha e
resume para o atendente, e porta para o cliente plugar a própria IA.

### 7. Construtor visual de fluxos (Twilio Studio, Blip)

Fluxos de automação desenhados no painel, versionados, com teste no sandbox.
Lição do Twilio: logs de execução de fluxo não são trilha de auditoria —
auditoria fica no nosso `audit_log`.

### 8. Ecossistema e canal de revenda

- Nós oficiais para **n8n, Make e Zapier** (Z-API tem; é expectativa de mercado).
- Integração com Chatwoot e Typebot (Evolution tem).
- **Plano parceiro/white-label** para agências: painel multi-cliente,
  cobrança centralizada (Z-API Partner).

### 9. Confiança como argumento de venda

Infobip vende certificações. Roteiro sugerido: controles alinhados à ISO 27001
desde o início (já temos boa parte: auditoria, cifragem, RLS, gestão de
segredos) e certificação quando houver receita que justifique.

## Fontes

- Z-API: [z-api.io](https://www.z-api.io/), [developer.z-api.io](https://developer.z-api.io/)
- Evolution API: [greptile.com/grepository/evolution-api](https://www.greptile.com/grepository/evolution-api), [easypanel.io/docs/templates/evolutionapi](https://easypanel.io/docs/templates/evolutionapi), [railway.com — Evolution API](https://railway.com/deploy/evolution-api-open-source-messaging-automation-platform--self-host-evolution-api)
- WAHA: [easypanel.io/docs/templates/waha](https://easypanel.io/docs/templates/waha), [sealos.io — WAHA](https://sealos.io/products/app-store/waha/), [railway.com — WAHA](https://railway.com/deploy/waha-self-hosted-whatsapp-rest-api--waha-api)
- Twilio: [changelog](https://www.twilio.com/en-us/changelog/2025), [Studio User Guide](https://www.twilio.com/docs/studio/user-guide.md), [Conversations GA](https://www.twilio.com/en-us/blog/products/launches/twilio-conversations-api-now-generally-available)
- Blip / Zenvia: [tiinside.com.br — Claro e Blip](https://tiinside.com.br/10/08/2026/claro-empresas-e-blip-lancam-parceria-com-foco-em-pmes-pelo-whatsapp/), [diariodocomercio.com.br — Blip](https://diariodocomercio.com.br/?p=624135), [itforum.com.br — Zenvia](https://itforum.com.br/?p=187760), [Capterra — Blip](https://www.capterra.com/p/200367/Blip/)
- respond.io / Wati / Gupshup / Infobip: [sleekflow.io — Gupshup alternatives](https://sleekflow.io/blog/gupshup-alternatives) (blog de concorrente), [Capterra — comparação](https://www.capterra.com.sg/compare/179311/204314/rocketbots/vs/wati)
- Chatwoot: [github.com/chatwoot/chatwoot](https://github.com/chatwoot/chatwoot), [chatwoot.com — Support Desk](https://www.chatwoot.com/product/support-desk), [eesel.ai — overview](https://www.eesel.ai/blog/chatwoot-overview)
- Svix: [svix.com](https://www.svix.com), [hookdeck.com — guia Svix](https://hookdeck.com/webhooks/platforms/guide-to-svix-webhooks-features-and-best-practices)
- Standard Webhooks: [svix.com — webhook signature](https://www.svix.com/resources/glossary/webhook-signature/), [pkg.go.dev — std-webhooks-go](https://pkg.go.dev/github.com/krofort/std-webhooks-go)
- Coexistência: [360dialog](https://docs.360dialog.com/docs/hub/embedded-signup/whatsapp-coexistence), [Telnyx](https://developers.telnyx.com/docs/messaging/whatsapp/coexistence), [8x8](https://developer.8x8.com/connect/docs/whatsapp/whatsapp-business-app-coexistence), [Meta — Embedded Signup V4](https://developers.facebook.com/documentation/business-messaging/whatsapp/embedded-signup/version-4-public-preview/)
- WhatsApp Flows e Pix: [360dialog — Flows](https://docs.360dialog.com/docs/waba-messaging/flows), [360dialog — Payments API Brazil](https://docs.360dialog.com/partner/commerce-and-payments/payments-api-brazil), [Mastermind — booking](https://mastermind.helpscoutdocs.com/article/1219-whatsapp-flows-in-app-appointment-booking)
