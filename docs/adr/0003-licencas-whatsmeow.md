# ADR-0003: Licenças — whatsmeow (MPL-2.0) e libsignal (GPL-3.0)

**Status:** Proposto — bloqueia a Fase 1
**Data:** 2026-10-20
**Decisores:** Gustavo; recomendável parecer jurídico antes de qualquer entrega on-prem

> Isto é análise de engenharia, não parecer jurídico.

## Contexto

O whatsmeow é MPL-2.0, mas **não é a única licença que entra no binário**.
Verificado em 2026-10-20:

- `go.mod` do whatsmeow (`github.com/tulir/whatsmeow`, branch `main`) requer
  `go.mau.fi/libsignal v0.2.2`.
- `go.mau.fi/libsignal` aponta para `github.com/tulir/libsignal-protocol-go`,
  cujo `LICENSE` é **GNU GPL v3**.

Go linka estaticamente. Então o binário que importa o whatsmeow também contém
código GPL-3.0.

### O que cada licença exige

**MPL-2.0 (copyleft por arquivo):**
- Usar sem modificar: ao distribuir o binário, informar a licença e disponibilizar
  o código-fonte dos arquivos MPL.
- Modificar arquivos do whatsmeow: as modificações nesses arquivos ficam sob
  MPL-2.0 e o fonte delas tem de ser disponibilizado a quem recebe o binário.
- Nosso código próprio pode ter qualquer licença.

**GPL-3.0 (copyleft da obra combinada):**
- Ao **distribuir** um binário que contém código GPL-3.0, a obra combinada inteira
  daquele binário tem de ser oferecida sob GPL-3.0, com fonte correspondente.
- Rodar como serviço sem entregar o binário (SaaS) **não** é distribuição na
  GPL-3.0 (diferente da AGPL).

## Decisão

1. **Isolar a dependência em um binário próprio** (`cmd/session-worker`). O control
   plane (`cmd/api`), o dispatcher e todo o resto não importam whatsmeow nem
   libsignal e se comunicam com o worker só por NATS, com mensagens em formato
   próprio. `depguard` no CI impede o import fora de `internal/session/...`.
2. **Não modificar arquivos do whatsmeow no nosso repositório.** Se for preciso
   um patch, ele vai num fork público, referenciado por `replace` no `go.mod`, e
   é proposto upstream.
3. **Modelo comercial: SaaS** (resposta à Q1 em 2026-10-20). O produto é vendido
   como serviço: o cliente opera pelo painel web e pela API, e nunca recebe
   binário. Nesse modelo nenhuma das duas licenças dispara obrigação de
   entregar fonte.
4. **Entrega on-prem está fora do escopo.** Proposta comercial ou contrato que
   ofereça instalação na infra do cliente exige um ADR novo antes de ser
   assinado: ou o worker é entregue com fonte sob GPL-3.0, ou o cliente on-prem
   recebe só o canal oficial. Decidir com advogado.
5. `go-licenses` no CI gera `THIRD_PARTY_NOTICES.md` e **falha** se aparecer
   licença fora da lista permitida (MIT, BSD, Apache-2.0, ISC, MPL-2.0, e GPL-3.0
   só no módulo do worker).

## Opções consideradas

- **A: binário único com tudo** — simples, mas qualquer distribuição contamina o
  produto inteiro com GPL-3.0.
- **B: worker isolado, SaaS (escolhida)** — isola o risco; custo: uma fronteira de
  processo que já existiria por causa do ADR-0005.
- **C: trocar de engine** — Baileys (MIT) muda a stack para TS e reabre a decisão
  2 da fundação. Não recomendado agora.

## Consequências

- A fronteira API ↔ worker é um contrato versionado (mensagens NATS).
- Separar binários por processo reduz o risco jurídico, mas não é garantia; o
  ponto "obra combinada vs agregação" é interpretação e precisa de advogado se
  houver distribuição.
- Revisitar: a cada upgrade do whatsmeow, reler `go.mod` e licenças (faz parte
  do runbook de upgrade).

## Itens de ação

1. [x] Q1 respondida: SaaS com painel, sem distribuição (2026-10-20).
2. [ ] Configurar `depguard` e `go-licenses` no CI.
3. [ ] Runbook `docs/runbooks/upgrade-whatsmeow.md` (Fase 1).
