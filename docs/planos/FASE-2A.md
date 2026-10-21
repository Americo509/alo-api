# Plano — Fase 2a: Identidade e autenticação

**Status:** Aguardando aprovação do PO
**Data:** 2026-10-20
**Base:** ADR-0007 (autenticação própria em Go), ADR-0009 (SPA + BFF), ADR-0006 (RLS)

## Objetivo e critério de saída

Usuário cria conta com e-mail e senha (ou Google/Apple), verifica o e-mail,
ativa MFA, entra no painel por sessão segura via BFF e pertence a um ou mais
tenants com papéis. **Saída:** checklist OWASP ASVS 5.0 nível 2 dos capítulos
de autenticação, sessão e OAuth com evidência por item; testes passando.

## Fora do escopo

Painel visual (Fase 2b), cobrança (2c), API keys de máquina (2b).

## Passos

| # | Passo | Entrega verificável |
|---|---|---|
| 2a.1 | Esquema `iam` | `users`, `user_password`, `user_identities`, `memberships`, `mfa_totp`, `webauthn_credentials`, `recovery_codes`, `auth_tokens`, `consents`, `access_logs` com RLS onde houver tenant; teste de catálogo estendido |
| 2a.2 | Senha | Argon2id (formato PHC, rehash transparente) + pepper no KMS; política NIST; checagem de senha vazada por k-anonimato; testes de vetores e de rehash |
| 2a.3 | Cadastro e verificação | Tokens de uso único guardados só como hash; respostas e tempos iguais exista ou não a conta (anti-enumeração), com teste de tempo |
| 2a.4 | Login e proteção contra força bruta | Limite por IP/conta/global no Redis, atraso progressivo, sem bloqueio permanente; testes com relógio falso |
| 2a.5 | Sessão (BFF) | Cookie `__Host-`