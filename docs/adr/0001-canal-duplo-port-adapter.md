# ADR-0001: Canal duplo com porta `CanalDeMensagem`

**Status:** Proposto
**Data:** 2026-10-20
**Decisores:** Gustavo (PO/arquiteto)

## Contexto

Os sistemas clientes precisam enviar e receber WhatsApp sem saber qual motor
está embaixo. Existem dois motores com propriedades muito diferentes:

| | Cloud API (oficial) | Engine não-oficial (whatsmeow) |
|---|---|---|
| Conteúdo fora da janela de 24h | Só template aprovado | Livre |
| Custo | Por mensagem | Infra |
| Risco de bloqueio do número | Baixo, regido por política da Meta | Alto, sem recurso |
| Identidade do remetente | Número oficial do tenant | Número da instância |

A decisão de ter os dois já foi tomada. Este ADR registra **como** a porta é
desenhada para que o roteamento e o failover funcionem de verdade.

## Decisão

1. **A porta recebe uma intenção, não um texto pronto.** O cliente envia
   `{tipo, destinatario, variaveis, idioma}` (ex.: `lembrete_consulta` com
   `{data, profissional}`). Cada adapter materializa a mensagem: o oficial
   escolhe o template aprovado mapeado para o tipo; o não-oficial renderiza o
   texto do catálogo do tenant. Texto livre só é aceito como tipo `texto_livre`,
   que **não tem failover** para o oficial fora da janela de 24h.

2. **Catálogo de tipos de mensagem por tenant**, cada tipo com: canal
   permitido (`oficial`, `nao_oficial`, `ambos`), template oficial vinculado
   (opcional), criticidade e se admite failover.

3. **Roteador como função pura** `Rotear(politica, tipo, estadoInstancia,
   estadoJanela) → Decisao{canal, motivo}`. Testável sem I/O. O motivo é
   gravado na mensagem para auditoria.

4. **Failover só do não-oficial para o oficial**, só para tipos que admitem e
   têm template aprovado. Nunca do oficial para o não-oficial (rebaixaria a
   garantia de um fluxo crítico).

5. Tipos marcados como críticos (ex.: plantão do CONECTA) são fixados em
   `oficial` e o roteador recusa outra rota.

Interface (esboço, não final):

```go
type CanalDeMensagem interface {
    Enviar(ctx context.Context, m domain.MensagemSaida) (domain.ReciboEnvio, error)
    Capacidades() domain.Capacidades // ex.: suporta texto livre? mídia? janela?
}
```

O recebimento não passa pela porta de envio: os dois adapters publicam
`domain.MensagemEntrada` normalizada num subject NATS comum.

## Opções consideradas

### A: porta recebe texto cru
**Prós:** API simples para o cliente. **Contras:** failover para o oficial é
impossível fora da janela; o roteador teria de adivinhar template.

### B: porta recebe intenção + variáveis (escolhida)
**Prós:** failover real, auditoria de motivo, catálogo vira ativo do tenant.
**Contras:** clientes precisam cadastrar tipos; mais trabalho na Fase 2.

### C: dois endpoints, cliente escolhe o canal
**Contras:** viola a decisão de o cliente não saber o motor.

## Consequências

- Mais fácil: failover, relatórios por tipo, revisão de conteúdo por tipo.
- Mais difícil: onboarding de tenant exige montar catálogo e aprovar templates.
- O contato recebe do número oficial quando há failover; a mensagem deve fazer
  sentido vinda de outro número (texto do template precisa se identificar).
- Revisitar: como expor `texto_livre` no atendimento humano/IA (Fase 5).

## Itens de ação

1. [ ] Modelar `message_types` no esquema da Fase 2.
2. [ ] Definir contrato OpenAPI do envio por intenção.
3. [ ] Testes de tabela do roteador cobrindo todas as combinações de estado.
