# Runbook — Login com Google e Apple

Itens que **só o dono da conta** pode fazer. O código já está pronto
(`oidclogin.GoogleConfig` / `AppleConfig`); falta credencial.

URLs de retorno (fixas, idênticas no provedor e na config):

- `https://<painel>/bff/auth/oidc/google/callback`
- `https://<painel>/bff/auth/oidc/apple/callback`

## Google

1. Google Cloud Console → projeto novo → **APIs e serviços → Tela de consentimento OAuth**.
   Tipo *Externo*; escopos apenas `openid`, `email`, `profile` (não sensíveis,
   sem verificação pesada). Preencha política de privacidade e termos (LGPD).
2. **Credenciais → Criar ID do cliente OAuth → Aplicativo da Web**.
   Origem autorizada: `https://<painel>`. URI de redirecionamento: a URL acima.
3. Guarde `client_id` (config) e `client_secret` (**Vault**, nunca no repositório).
4. Publique o app (*Em produção*), senão só usuários de teste entram.

## Apple

1. Conta **Apple Developer** (paga, US$ 99/ano).
2. Identifiers → **App ID** com *Sign in with Apple* habilitado.
3. Identifiers → **Services ID** (será o `client_id`); habilite *Sign in with Apple*,
   configure o domínio `<painel>` e a URL de retorno acima (a Apple exige https e
   domínio verificado; localhost não funciona).
4. Keys → nova chave com *Sign in with Apple*; baixe o `.p8` **uma única vez**.
   Anote o **Key ID** e o **Team ID**.
5. A chave privada vai para o **Vault/KMS** (idealmente como `crypto.Signer`
   remoto). O `client_secret` é um JWT ES256 gerado a cada uso (`AppleSecret`).
6. A Apple só envia nome/e-mail no **primeiro** login; o e-mail pode ser relay
   privado. A identidade é sempre `(issuer, subject)`, nunca o e-mail.

## Regras que não mudam

- Nunca vincular contas automaticamente por e-mail (ADR-0007).
- Segredos só no cofre; rotacionar a chave Apple e o secret do Google a cada 12 meses.
- Teste local: usar o Google com `http://localhost` é aceito; Apple exige staging https.
