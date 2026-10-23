# ADR-0009: Front-end separado (SPA) com BFF

**Status:** Aceito (implementado na Fase 2a)
**Data:** 2026-10-20
**Decisores:** Gustavo

## Contexto

Decisão do PO (Q9, 2026-10-20): o painel é um **front-end separado**, com
qualidade de produto de big tech. A pergunta sobre app mobile segue aberta (Q21).

Uma SPA traz a questão de onde ficam os tokens. A recomendação atual do IETF
para aplicações OAuth no navegador (*OAuth 2.0 for Browser-Based Applications*)
coloca o padrão **Backend-for-Frontend (BFF)** como o mais seguro: o navegador
não guarda nenhum token, só um cookie de sessão `HttpOnly`.

## Decisão

### 1. Topologia

- SPA e BFF na **mesma origem** (`app.<dominio>`), com proxy reverso:
  `/` → arquivos estáticos da SPA, `/bff/*` → BFF em Go.
- Mesma origem = **sem CORS**, cookie `__Host-` funciona, `SameSite=Lax` protege.
- API pública continua em `api.<dominio>/v1/*` com API key. **BFF e API pública
  são superfícies separadas:** endpoints do BFF não aceitam API key; a API
  pública não aceita cookie de sessão.
- Mídia servida por URL pré-assinada de vida curta em **domínio separado**
  (`media.<dominio-de-midia>`, sem cookies), para que um arquivo malicioso
  (SVG, HTML) enviado por um contato nunca execute na origem do painel.

### 2. Stack do front

| Área | Escolha proposta |
|---|---|
| Base | React 19 + TypeScript `strict` + Vite |
| Rotas | TanStack Router (rotas e parâmetros tipados) |
| Dados | TanStack Query; cliente HTTP **gerado do OpenAPI** (o contrato é a fonte da verdade; quebrou o contrato, quebra o build do front) |
| UI | Design system próprio sobre Radix (acessibilidade pronta) + Tailwind, com tokens de design; base inicial shadcn/ui |
| Formulários | React Hook Form + Zod (mesmas regras de validação que o backend publica no OpenAPI) |
| Tempo real | Server-Sent Events para status e eventos; WebSocket só na inbox, se necessário |
| i18n | pt-BR primeiro, estrutura pronta para en/es |
| Testes | Vitest + Testing Library; Playwright (e2e) contra o modo sandbox; Storybook com teste visual; axe para acessibilidade |
| Qualidade | WCAG 2.2 AA; orçamento de performance (Core Web Vitals) verificado no CI |
| Monitoramento | Erros e performance do navegador via OpenTelemetry, com remoção de PII antes de enviar |

### 3. Segurança do front

- **Nenhum token no navegador.** Sem `localStorage`/`sessionStorage` para
  credenciais.
- CSP estrita com `nonce`/hash, **Trusted Types** ativado, sem
  `dangerouslySetInnerHTML` (lint bloqueia).
- **Conteúdo de mensagem é hostil.** Texto de contato é renderizado como texto;
  a formatação do WhatsApp (`*negrito*`, `_itálico_`) passa por um parser
  próprio que gera elementos React, nunca HTML.
- Links em mensagens: `rel="noopener noreferrer"`, aviso antes de abrir domínio
  externo.
- Dependências: lockfile, auditoria no CI, atualização automatizada com
  revisão, Subresource Integrity em qualquer recurso externo.
- Ações sensíveis (gerar API key, apagar dados) pedem reautenticação (ADR-0007).

### 4. Repositório

O front fica **no mesmo monorepo**, em `web/`, com `pnpm`. Assim, mudança no
`api/openapi.yaml` regenera o cliente TypeScript no mesmo PR e o CI testa os
dois lados juntos.

## Opções consideradas

- **SPA + tokens no navegador:** mais simples, mas exposta a roubo por XSS.
- **SPA + BFF (escolhida):** padrão mais seguro recomendado pelo IETF.
- **Next.js com servidor Node como BFF:** adiciona um segundo backend em outra
  linguagem; o BFF em Go reaproveita sessão, RLS e auditoria.

## Consequências

- ADR-0007, item 7: o painel usa sessão opaca via BFF. JWT de acesso só entra
  se houver app mobile (Q21).
- O BFF é uma camada fina: autentica, aplica entitlement (ADR-0008) e chama os
  mesmos serviços internos da API pública.
- Revisitar: SSR para páginas públicas (site, docs) é outro projeto, fora do painel.

## Contrato implementado (Fase 2a, `internal/bff`)

Rotas sob `/bff/auth/*`. Links enviados por e-mail levam o token no
**fragmento** (`#token=...`), que não chega a logs de servidor nem a `Referer`:
`/auth/verify-email`, `/auth/reset-password`, `/auth/login`, `/auth/mfa`,
`/settings/security`. O SPA lê o fragmento e envia o token por POST JSON.
Cookie `__Host-session`; token CSRF em cabeçalho; erros em `problem+json`.
