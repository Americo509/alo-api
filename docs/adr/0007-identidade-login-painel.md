# ADR-0007: Identidade e autenticação implementadas em Go

**Status:** Proposto
**Data:** 2026-10-20
**Decisores:** Gustavo

## Contexto

O produto é SaaS com painel (Q1). Decisões do PO (Q15, 2026-10-20):

- Cadastro próprio com **e-mail e senha** é o caminho principal.
- **Google, Apple e outros** são atalhos opcionais de login.
- A autenticação inteira é **implementada por nós, em Go** (opção A), com o
  padrão mais alto de mercado, sem vazar credencial nem dado sensível e em
  conformidade com a LGPD.

Há dois tipos de acesso que não se misturam:

- **Usuários humanos** no painel → este ADR.
- **Sistemas** do cliente na API → API key (hash Argon2id, escopo, rotação).
  Login nunca gera API key implicitamente.

### Nota do engenheiro (registrada, decisão é do PO)

Autenticação própria é o código onde um erro custa mais. Para compensar,
este ADR adota três contrapesos obrigatórios: **OWASP ASVS 5.0 nível 2** como
critério de aceite verificável, uso só de bibliotecas criptográficas maduras
(nada de primitiva escrita à mão) e **pentest externo antes da venda**.

## Decisão

### 1. Padrões de referência

- **OWASP ASVS 5.0, nível 2:** os capítulos de autenticação, sessão, tokens e
  OAuth/OIDC viram checklist de teste na Fase 2.
- **NIST SP 800-63B** para política de senha e autenticadores.
- **OAuth 2.0 Security Best Current Practice (RFC 9700)** e OIDC Core para login
  social.
- **RFC 8725** (boas práticas de JWT).

### 2. Senha

- Hash **Argon2id** (`golang.org/x/crypto/argon2`), parâmetros configuráveis,
  com piso no mínimo recomendado pela OWASP (m=19 MiB, t=2, p=1). Calibrar para
  ~250–500 ms no hardware de produção. Parâmetros gravados junto do hash
  (formato PHC) para permitir **rehash transparente** quando forem elevados.
- **Pepper:** HMAC-SHA256 da senha com chave mantida no KMS/Vault antes do
  Argon2id. Vazou o banco, os hashes não são atacáveis offline sem a chave.
  Versão do pepper gravada para permitir rotação.
- Política (NIST): mínimo de 12 caracteres (configurável), aceitar até 128,
  qualquer caractere Unicode (normalizado NFKC), **sem regras de composição**
  e **sem expiração periódica**.
- Bloquear senhas conhecidamente vazadas pela API *Pwned Passwords* com
  k-anonimato: só os 5 primeiros caracteres do SHA-1 saem do servidor, nunca a
  senha. Se o serviço estiver fora, aceitar e reavaliar no próximo login.
- Troca de senha exige senha atual + reautenticação recente e **encerra todas
  as outras sessões**.

### 3. Cadastro, verificação e recuperação

- E-mail verificado antes de qualquer ação além de configurar a conta.
- Tokens de verificação e recuperação: 256 bits aleatórios (`crypto/rand`),
  **guardados só como hash** no banco, uso único, expiração curta (recuperação:
  30 min). Nunca JWT para isso: precisa ser revogável.
- **Anti-enumeração:** cadastro, login e "esqueci a senha" respondem igual,
  com o mesmo tempo, exista ou não a conta. No login com usuário inexistente,
  calcular um Argon2id falso para igualar o tempo.
- E-mail de aviso em: novo login de dispositivo desconhecido, troca de senha,
  alteração de MFA, novo vínculo de provedor, geração de API key.

### 4. Proteção contra força bruta

- Limite por IP, por conta e global (Redis, token bucket), com atraso
  progressivo.
- **Sem bloqueio permanente de conta** (vira ataque de negação de serviço contra
  o usuário). Bloqueio temporário + desafio anti-bot depois de N falhas.
- Alerta de credential stuffing: pico de falhas distribuídas em muitas contas.

### 5. MFA

- **Passkeys / WebAuthn** (`go-webauthn/webauthn`): método preferido,
  resistente a phishing. Pode inclusive substituir a senha.
- **TOTP** (RFC 6238): segredo cifrado com envelope encryption, janela de ±1
  passo, código já usado é rejeitado (anti-replay).
- **Códigos de recuperação:** 10 códigos, cada um guardado como hash, uso único.
- Obrigatório para `dono`, `admin` do tenant e `platform_admin`. Opcional e
  incentivado para os demais papéis.
- **Sem SMS** como segundo fator (vulnerável a SIM swap).

### 6. Login social (Google, Apple e outros)

- Fluxo **Authorization Code + PKCE (S256)**, com `state` e `nonce` aleatórios
  amarrados à sessão pré-login. Bibliotecas: `golang.org/x/oauth2` +
  `coreos/go-oidc`.
- Validação do `id_token`: assinatura pela JWKS do provedor (com cache e
  rotação), `iss`, `aud`, `exp`, `iat`, `nonce`. Só algoritmos esperados.
- Identidade = par `(issuer, subject)`. **Nunca o e-mail.**
- **Vínculo de conta:** se o e-mail do provedor já existe com senha, **não**
  vincula automaticamente (risco de tomada de conta). O usuário entra com a
  senha e vincula pelo painel.
- Escopos mínimos: `openid email profile`.
- **Apple:** o `client_secret` é um JWT assinado com chave privada da Apple
  (guardada no KMS, renovado antes de expirar); resposta via `form_post`; nome do
  usuário só vem no primeiro login; e-mail pode ser de encaminhamento ("Ocultar
  meu e-mail"). Exige conta paga no Apple Developer Program.
- **Google:** verificação do app pelo Google para sair do modo de teste.
- Provedores são adapters de uma interface; adicionar Microsoft ou outro é
  configuração + adapter.

### 7. Sessão do painel e uso de JWT

**Discordância registrada (regra 4):** JWT não é o melhor mecanismo para a
sessão de um painel web. Ele não pode ser revogado antes de expirar (logout,
senha trocada, usuário removido continuam valendo) e, se ficar acessível ao
JavaScript, um XSS rouba a sessão. O padrão mais seguro para navegador é sessão
opaca no servidor. Proposta:

- **Atualização (Q9, 2026-10-20):** o painel é SPA separada; a sessão opaca é
  mantida pelo BFF na mesma origem (ADR-0009). O navegador não guarda token.
- **Painel (navegador): sessão opaca.** ID de 256 bits em cookie
  `__Host-session`, `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/`. No Redis
  guarda-se só o **hash** do ID. Expiração por inatividade e expiração absoluta.
  ID trocado no login e em mudança de privilégio (anti-fixação). Revogação
  instantânea; tela "sessões ativas" com encerrar sessão.
- **Reautenticação (step-up)** para ações sensíveis: trocar senha/MFA, gerar API
  key, exportar ou apagar dados, ações de `platform_admin`.
- **JWT onde ele é a ferramenta certa:**
  - validar `id_token` dos provedores sociais;
  - **access token curto** (5–15 min) se houver SPA em outro domínio ou app
    mobile (depende da Q9), com **refresh token opaco, rotativo e com detecção
    de reuso** (reuso revoga a família inteira);
  - futuramente, se o produto virar servidor OAuth para integrações de terceiros.
- **Endurecimento do JWT (RFC 8725):** algoritmo fixo por chave (EdDSA ou
  ES256), lista branca, `alg: none` e confusão HS/RS rejeitados; `kid`
  obrigatório; validação de `iss`, `aud`, `exp`, `nbf`; chaves privadas no
  KMS, rotação periódica, JWKS publicado com chave antiga até expirar o último
  token. **Nenhum dado pessoal nas claims**: JWT é só codificado, não cifrado.
  Biblioteca: `golang-jwt/jwt/v5` ou `lestrrat-go/jwx`, a decidir no plano da Fase 2.

### 8. Proteções web

- CSRF: `SameSite` + token sincronizador nos formulários + checagem de `Origin`.
- Cabeçalhos: CSP estrita (sem `unsafe-inline`), HSTS com preload,
  `frame-ancestors 'none'`, `Referrer-Policy: strict-origin-when-cross-origin`,
  `X-Content-Type-Options: nosniff`.
- Redirecionamento pós-login só para caminhos internos em lista branca
  (anti open-redirect).

### 9. LGPD e Marco Civil

- **Minimização:** guardamos e-mail, nome, `(issuer, subject)` e o que o usuário
  informar. Nada de foto, contatos ou outros escopos do provedor.
- **Consentimento e termos:** aceite de termos de uso e política de privacidade
  gravado com versão, data e IP.
- **Registros de acesso:** o Marco Civil da Internet (art. 15) obriga provedor de
  aplicação a guardar registros de acesso (IP, data e hora) por 6 meses, sob
  sigilo. Guardados **cifrados**, com acesso auditado e descarte automático após
  o prazo. Confirmar prazos com jurídico.
- **Direitos do titular** no painel: exportar meus dados (portabilidade),
  corrigir, excluir conta. Exclusão anonimiza o usuário e mantém só o que a lei
  obriga a guardar, pelo prazo legal.
- **Incidente de segurança:** runbook com comunicação à ANPD e aos titulares no
  prazo do regulamento de incidentes da ANPD (confirmar prazo vigente com
  jurídico).
- **Logs:** senha, token, código MFA, cookie e `id_token` nunca são logados.
  Teste automatizado procura esses padrões na saída de log.

### 10. Segredos

Pepper, chaves de assinatura JWT, `client_secret` dos provedores, chave privada
da Apple e chaves de cifragem do TOTP ficam no KMS/Vault. Nada em código,
repositório ou variável de ambiente em texto claro.

## Modelo de dados (adicional)

`users`, `user_password` (hash PHC, versão do pepper), `user_identities`
(issuer, subject), `memberships` (user, tenant, papel), `mfa_totp` (segredo
cifrado), `webauthn_credentials`, `recovery_codes` (hash), `auth_tokens`
(verificação/recuperação, só hash), `refresh_tokens` (hash, família, reuso),
`consents` (documento, versão, data), `access_logs` (cifrado, retenção 6 meses).
Sessões ativas no Redis, com índice por usuário para "encerrar todas".

## Opções consideradas

- **A: implementar em Go (escolhida pelo PO).** Controle total e dados na sua
  infra; maior responsabilidade de segurança, mitigada pelos contrapesos acima.
- **B: IdP open source auto-hospedado** e **C: IdP gerenciado.** Recomendadas
  pelo engenheiro, não adotadas.

## Critério de aceite (entra na definição de pronto da Fase 2)

1. Checklist ASVS 5.0 nível 2 dos capítulos de autenticação, sessão, tokens e
   OAuth/OIDC, com evidência (teste automatizado ou justificativa) por item.
2. Testes automatizados: enumeração por tempo e por resposta, fixação de sessão,
   CSRF, open redirect, reuso de refresh token, `alg` inválido, `nonce`/`state`
   errados, token expirado, rehash de parâmetros.
3. Fuzzing (`go test -fuzz`) dos parsers de token e de cookie.
4. Testes de integração com provedor OIDC simulado local.
5. Pentest externo antes de abrir venda.

## Consequências

- A Fase 2 cresce. Proposta: dividir em **2a (identidade)** e **2b (tenants,
  API, liberação manual)**, e a cobrança automática vira **2c** (ADR-0008).
- Toda atualização das bibliotecas de autenticação passa por `govulncheck` e
  revisão.
- Revisitar quando houver app mobile ou integração OAuth de terceiros.
