# Architecture Decision Records

| ADR | Título | Status |
|-----|--------|--------|
| [0001](0001-canal-duplo-port-adapter.md) | Canal duplo com porta `CanalDeMensagem` | Proposto |
| [0002](0002-stack.md) | Stack tecnológica | Proposto |
| [0003](0003-licencas-whatsmeow.md) | Licenças: whatsmeow (MPL-2.0) e libsignal (GPL-3.0) | Proposto — **bloqueia Fase 1** |
| [0004](0004-aceite-risco-tos.md) | Aceite de risco de ToS do engine não-oficial | Proposto — **requer assinatura** |
| [0005](0005-lease-sessao-fencing.md) | Uma sessão, um worker: lease + fencing token | Proposto |
| [0006](0006-isolamento-tenant-rls.md) | Isolamento por tenant com RLS | Proposto |
| [0007](0007-identidade-login-painel.md) | Identidade e autenticação em Go (senha, MFA, Google, Apple…) | Proposto |
| [0008](0008-acesso-por-assinatura.md) | Acesso por pagamento ou liberação manual | Proposto — falta gateway |
| [0009](0009-frontend-spa-bff.md) | Front-end separado (SPA) com BFF | Proposto |

**Fase 0 encerrada em 2026-10-20:** o PO aprovou a direção e o início da Fase 1.
Os ADRs 0001–0009 passam a valer como decisões vigentes; o aceite formal de
risco do ADR-0004 (tabela de assinatura) segue pendente.

Status possíveis: Proposto → Aceito → (Substituído por ADR-XXXX | Obsoleto).
ADR aceito não é editado; mudança de decisão vira ADR novo que o substitui.
