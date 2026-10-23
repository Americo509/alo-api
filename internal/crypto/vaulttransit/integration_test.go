//go:build integration

package vaulttransit

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/Americo509/alo-api/internal/crypto/envelope"
)

const (
	vaultImage = "hashicorp/vault:1.21.4"
	rootToken  = "root-de-teste-integracao"
)

// startVault sobe um Vault em modo dev, habilita o Transit e cria a chave.
func startVault(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	c, err := testcontainers.Run(ctx, vaultImage,
		testcontainers.WithEnv(map[string]string{
			"VAULT_DEV_ROOT_TOKEN_ID":  rootToken,
			"VAULT_DEV_LISTEN_ADDRESS": "0.0.0.0:8200",
		}),
		testcontainers.WithExposedPorts("8200/tcp"),
		testcontainers.WithWaitStrategy(wait.ForHTTP("/v1/sys/health").WithPort("8200/tcp").WithStartupTimeout(60*time.Second)),
	)
	testcontainers.CleanupContainer(t, c)
	if err != nil {
		t.Fatalf("subir vault: %v", err)
	}
	ep, err := c.PortEndpoint(ctx, "8200/tcp", "http")
	if err != nil {
		t.Fatalf("endpoint: %v", err)
	}
	admin(t, ep, "sys/mounts/transit", `{"type":"transit"}`)
	admin(t, ep, "transit/keys/sessions", `{"type":"aes256-gcm96"}`)
	return ep
}

func admin(t *testing.T, addr, path, body string) {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, addr+"/v1/"+path, strings.NewReader(body))
	req.Header.Set("X-Vault-Token", rootToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("admin %s: %v", path, err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		t.Fatalf("admin %s: status %d", path, resp.StatusCode)
	}
}

func TestIntegrationVaultTransit(t *testing.T) {
	addr := startVault(t)
	c, err := New(Config{Addr: addr, KeyName: "sessions", Token: StaticToken(rootToken), AllowInsecureHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	svc := envelope.New(c)
	ctx := context.Background()
	aad := []byte("instance:integracao/field:noise_key")

	dk, w, err := svc.GenerateKey(ctx)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if !bytes.HasPrefix(w.Ciphertext, []byte("vault:v1:")) {
		t.Fatalf("ciphertext inesperado: %.20s…", w.Ciphertext)
	}
	sealed, err := dk.Seal([]byte("estado de sessão"), aad)
	if err != nil {
		t.Fatal(err)
	}

	// Rotação da chave mestra no Vault + rewrap da DEK.
	admin(t, addr, "transit/keys/sessions/rotate", `{}`)
	rw, err := svc.Rewrap(ctx, w)
	if err != nil {
		t.Fatalf("Rewrap: %v", err)
	}
	if !bytes.HasPrefix(rw.Ciphertext, []byte("vault:v2:")) {
		t.Fatalf("rewrap não usou a versão 2: %.20s…", rw.Ciphertext)
	}
	dk2, err := svc.OpenKey(ctx, rw)
	if err != nil {
		t.Fatalf("OpenKey: %v", err)
	}
	got, err := dk2.Open(sealed, aad)
	if err != nil || string(got) != "estado de sessão" {
		t.Fatalf("Open após rotação = %q, %v", got, err)
	}

	// Token sem permissão é recusado pelo Vault.
	bad, _ := New(Config{Addr: addr, KeyName: "sessions", Token: StaticToken("invalido"), AllowInsecureHTTP: true})
	if _, err := bad.Wrap(ctx, make([]byte, 32)); err == nil {
		t.Fatal("Vault aceitou token inválido")
	} else {
		t.Logf("recusa esperada: %v", err)
	}
}
