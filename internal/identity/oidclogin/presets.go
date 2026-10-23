package oidclogin

import (
	"errors"
	"strings"
)

const (
	googleIssuer = "https://accounts.google.com"
	appleIssuer  = "https://appleid.apple.com"
)

// GoogleConfig monta a configuração do Google. O redirectURL deve ser idêntico
// ao cadastrado no Google Cloud Console (docs/runbooks/login-social.md).
func GoogleConfig(clientID string, secret SecretSource, redirectURL string) (ProviderConfig, error) {
	if strings.TrimSpace(clientID) == "" || secret == nil {
		return ProviderConfig{}, errors.New("oidclogin: Google exige client_id e segredo")
	}
	return ProviderConfig{
		Name: "google", Issuer: googleIssuer, ClientID: clientID, RedirectURL: redirectURL,
		Scopes: []string{"openid", "email", "profile"}, Secret: secret,
	}, nil
}

// AppleConfig monta a configuração do Sign in with Apple. clientID é o Services
// ID. A Apple devolve o callback por POST cross-site (form_post), o que o BFF
// trata por stash + redirecionamento 303.
func AppleConfig(secret AppleSecret, redirectURL string) (ProviderConfig, error) {
	if secret.TeamID == "" || secret.ClientID == "" || secret.KeyID == "" || secret.Signer == nil {
		return ProviderConfig{}, errors.New("oidclogin: Apple exige team_id, services id, key_id e chave")
	}
	return ProviderConfig{
		Name: "apple", Issuer: appleIssuer, ClientID: secret.ClientID, RedirectURL: redirectURL,
		Scopes: []string{"openid", "email", "name"}, Secret: secret, FormPost: true,
	}, nil
}
