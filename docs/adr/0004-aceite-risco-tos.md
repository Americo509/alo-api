# ADR-0004: Aceite de risco de ToS do engine não-oficial

**Status:** Salvaguardas 6 a 13 aprovadas pelo PO em 2026-10-20 — aceite formal
de risco (tabela de assinatura) ainda pendente
**Data:** 2026-10-20
**Decisores:** Gustavo (e, por tenant, o responsável de cada cliente que optar pelo canal)

## Contexto

Os termos do WhatsApp não autorizam acesso ao serviço por clientes
não-oficiais ou automatizados fora dos produtos de API da Meta. O engine
baseado em whatsmeow opera fora desse uso autorizado. Não é, por si, ilícito
penal, mas gera:

- **Risco operacional:** o número pode ser restrito ou banido a qualquer momento,
  sem aviso e sem recurso.
- **Risco contratual:** cliente que exige conformidade com termos de terceiros
  (contrato público, por exemplo) pode considerar inadimplemento.
- **Risco de dado:** mensagens com dado de saúde num canal sem garantia de
  continuidade e sem contrato com a Meta.
- **Risco técnico:** mudanças de protocolo podem quebrar o engine até o
  mantenedor publicar correção.

### Venda a terceiros (Q1, 2026-10-20)

O produto será vendido como SaaS. Isso muda o perfil do risco: deixa de ser um
canal usado só pelos seus sistemas e passa a ser um serviço comercial oferecido
a clientes que você não controla. Consequências:

- A plataforma passa a responder pelo uso que os clientes fazem do canal. Um
  cliente que dispare spam coloca em risco a reputação da plataforma inteira e
  pode expor você contratualmente.
- O motor de políticas (Fase 3) passa a ser também controle contra abuso pelos
  próprios clientes, não só proteção do número.
- Os termos de uso da plataforma precisam proibir spam e envio sem opt-in, e
  prever suspensão do tenant.

**Decisão do PO (Q1a, 2026-10-20):** clientes pagantes **terão** acesso ao canal
não-oficial. A recomendação de lançar só com o oficial foi registrada e não
adotada. As salvaguardas abaixo (itens 6 a 10) passam a ser condição para
oferecer o canal a terceiros.

## Decisão

1. O canal não-oficial é **opt-in por tenant**, desligado por padrão. Ativar
   exige registro do aceite (quem, quando, versão deste documento e dos termos
   de uso) no `audit_log`.
2. **Proibido para:** fluxos marcados como críticos, qualquer tenant B2G e o
   fluxo de plantão do CONECTA. O roteador (ADR-0001) aplica isso; não é
   configuração que o tenant possa sobrescrever.
3. **Kill switch global e por tenant:** um comando desliga o canal não-oficial e
   faz o roteador tratar todas as instâncias não-oficiais como indisponíveis.
4. **Sem SLA** para o canal não-oficial nos termos comerciais da plataforma.
5. Revisão deste ADR a cada 6 meses ou quando houver mudança nos termos da Meta.

Salvaguardas para clientes externos (propostas, aguardando aprovação):

6. **Piso da plataforma não desligável.** Opt-in obrigatório, "SAIR" imediato e
   tetos mínimos do motor de políticas valem para todo tenant. O tenant pode
   deixar as regras mais restritivas, nunca mais frouxas que o piso.
7. **Termos de uso** proíbem spam, lista comprada e envio sem consentimento, e
   preveem suspensão sem aviso em caso de abuso.
8. **Identificação do cliente** no cadastro (CNPJ ou CPF, responsável, contato).
   Sem cliente identificado, sem canal não-oficial.
9. **Controle de abuso por tenant** (Fase 3): taxa de opt-out, bloqueios e
   denúncias por tenant; acima do limite, o canal do tenant é suspenso
   automaticamente e o caso vai para revisão.
10. **Liberação para externos só após o critério de saída da Fase 3**, com
    piloto nos seus sistemas internos primeiro.

Tenants de saúde (Q2, 2026-10-20: **podem** usar o canal não-oficial).
Condições propostas, aguardando aprovação:

11. Tenant que declara atuar em saúde marca isso no cadastro e registra a base
    legal do tratamento (LGPD art. 11) antes de ativar o canal não-oficial.
12. Nesses tenants, o canal não-oficial aceita só tipos de mensagem logísticos
    do catálogo (agendamento, lembrete, confirmação de horário). Conteúdo
    clínico (diagnóstico, prescrição, resultado de exame) fica restrito ao canal
    oficial. A restrição é por tipo de mensagem (ADR-0001), não por análise do
    texto.
13. O aceite do tenant de saúde inclui ciência explícita de que o canal não tem
    garantia de continuidade nem contrato com a Meta.

## Consequências

- Contratos com clientes precisam de cláusula explícita sobre o canal.
- O uso por tenants que tratam dado de saúde fica condicionado à resposta da
  PERGUNTAS-ABERTAS Q2.

## Assinatura

| Papel | Nome | Data | Decisão |
|-------|------|------|---------|
| Responsável pela plataforma | | | |
