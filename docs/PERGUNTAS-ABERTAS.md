# Perguntas abertas

Ordenadas pelo que bloqueia primeiro. Responda uma de cada vez; cada resposta
atualiza o ADR indicado.

## Bloqueiam a Fase 1

~~**Q1 — Distribuição on-prem.**~~ **Respondida (2026-10-20):** produto vendido
como SaaS, com painel para os clientes operarem. Sem entrega de binário.
Registrado no ADR-0003; impacto de venda a terceiros registrado no ADR-0004.

~~**Q1a — Canal não-oficial para clientes externos.**~~ **Respondida
(2026-10-20):** sim, clientes pagantes terão acesso. Salvaguardas propostas no
ADR-0004, itens 6 a 10, aguardando aprovação.

~~**Q2 — Dado de saúde no canal não-oficial.**~~ **Respondida (2026-10-20):**
podem usar. Condições propostas no ADR-0004, itens 11 a 13, aguardando aprovação.

**Q3 — Hospedagem.** Onde roda? Isso decide KMS gerenciado (AWS KMS, GCP KMS)
vs Vault próprio, Postgres gerenciado vs próprio e se `pg_partman`/`pgvector`
estão disponíveis. Requisito de dados no Brasil?

**Q4 — Número de teste.** Existe um chip dedicado para a Fase 1, sem uso
pessoal e sem histórico? O critério "72h estável" precisa de um número que
possa ser perdido sem prejuízo.

~~**Q5 — Repositório.**~~ **Respondida (2026-10-23):** produto **Alô API**; repositório
privado `github.com/Americo509/alo-api`, que também é o module path do Go.

## Bloqueiam a Fase 2

**Q6 — Webhook compatível?** Os sistemas clientes já integram com algum
provedor (Z-API, Evolution)? Se sim, vale um formato de webhook compatível
para migrar sem reescrever os clientes, ou fazemos formato próprio?

**Q7 — Papel na LGPD.** Para cada tenant, você é operador e o cliente
(prefeitura, nutricionista) é controlador? Isso define DPA, quem responde ao
titular e o fluxo de exclusão/portabilidade.

**Q8 — Store do auth state.** Na Fase 1 vou ler `store/sqlstore` do whatsmeow
para ver se dá para encaixar cifragem e fencing token nele ou se precisamos
de uma implementação própria das interfaces de store. Você prefere que eu traga
essa análise como ADR-0007 antes de codar? *(recomendo que sim)*

~~**Q9 — Painel do cliente.**~~ **Respondida (2026-10-20):** front separado,
nível big tech, com diferenciais sobre a Z-API. Desenho no ADR-0009; catálogo de
diferenciais em DIFERENCIAIS.md.

**Q21 — App mobile.** Haverá app mobile (para o atendente responder pelo
celular, por exemplo)? Se sim, entra JWT de acesso curto + refresh rotativo
(ADR-0007, item 7).

~~**Q22 — Diferenciais de lançamento.**~~ **Respondida (2026-10-20):** aprovados,
junto com as salvaguardas 6 a 13 e a divisão da Fase 2 em 2a/2b/2c.

~~**Q23 — Coexistência como padrão.**~~ **Respondida (2026-10-20):** aprovada.
Coexistência é o caminho padrão de onboarding; não-oficial como alternativa.
Itens 10 a 15 de DIFERENCIAIS aprovados junto.

~~**Q15 — Quem implementa o login.**~~ **Respondida (2026-10-20):** nós, em Go
(opção A). Cadastro com e-mail e senha como caminho principal; Google, Apple e
outros como atalho. Desenho completo no ADR-0007.

**Q20 — E-mail transacional.** Verificação de conta e recuperação de senha
precisam de um serviço de envio de e-mail (Amazon SES, Resend, Postmark,
SendGrid…), com SPF, DKIM e DMARC no domínio. Qual usar, e qual domínio?

**Q16 — Papéis no painel.** Proposta: `dono`, `admin`, `operador` (atende
conversas), `leitura`. Atende?

~~**Q17 — Cadastro.**~~ **Respondida (2026-10-20):** cadastro self-service por
login social; acesso só com pagamento ou liberação manual. *(ADR-0008)*

**Q18 — Gateway de pagamento.** Qual gateway (Asaas, Stripe, Pagar.me, Mercado
Pago, Iugu…)? Critérios: Pix e boleto recorrentes, cartão, webhook assinado,
emissão de nota fiscal. E você concorda em dividir a Fase 2 em 2 (liberação
manual) e 2b (pagamento automático)? *(ADR-0008)*

**Q19 — Trial.** Novo cadastro ganha teste grátis com prazo, ou fica sem
acesso até pagar/ser liberado?

## Ferramentas (proponho o default; só responda se discordar)

**Q10** — HTTP: stdlib `net/http`. **Q11** — Migrations: `goose`.
**Q12** — Logger: `slog` com ponte para o zerolog do whatsmeow.
**Q13** — Deploy inicial: Docker Compose em VM, K8s depois.

## Cloud API (Fase 4, mas tem prazo longo)

**Q14** — A Meta permite que uma plataforma SaaS ofereça a Cloud API aos
próprios clientes pelo programa **Tech Provider**: você cria um app Meta,
verifica a empresa, passa pelo App Review e depois cada cliente conecta a
própria conta WhatsApp Business pelo **Embedded Signup**, dentro do seu painel
(fonte: developers.facebook.com, guia "Get started for Tech Providers",
consultado em 2026-10-20). Quer seguir por esse caminho (você vira Tech
Provider) ou por um BSP parceiro? Verificação e App Review levam tempo; vale
começar antes da Fase 4.
