// Copyright (c) 2026 Peter Horrigan
// SPDX-License-Identifier: MPL-2.0

package snowflakepat

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

// generateTestPrivateKeyPEM generates a fresh RSA-2048 private key and returns
// it as a PEM-encoded PKCS8 string. No key material is hard-coded in the repo.
func generateTestPrivateKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	return string(pem.EncodeToMemory(block))
}

func TestConfig_WriteRead(t *testing.T) {
	b, storage := newTestBackend(t)
	ctx := context.Background()

	// Write config
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"account":     "myorg-myaccount",
			"username":    "admin_user",
			"private_key": generateTestPrivateKeyPEM(t),
			"database":    "mydb",
		},
	}
	resp, err := b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.Nil(t, resp)

	// Read config back
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, "myorg-myaccount", resp.Data["account"])
	require.Equal(t, "admin_user", resp.Data["username"])
	require.Equal(t, "mydb", resp.Data["database"])
	require.NotContains(t, resp.Data, "private_key", "private_key must not be returned")
}

func TestConfig_Delete(t *testing.T) {
	b, storage := newTestBackend(t)
	ctx := context.Background()

	// Write then delete
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"account":     "myorg-myaccount",
			"username":    "admin_user",
			"private_key": generateTestPrivateKeyPEM(t),
		},
	}
	_, err := b.HandleRequest(ctx, req)
	require.NoError(t, err)

	req = &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "config",
		Storage:   storage,
	}
	resp, err := b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.Nil(t, resp)

	// Read should return error response
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.True(t, resp.IsError())
}

func TestConfig_MissingRequired(t *testing.T) {
	b, storage := newTestBackend(t)
	ctx := context.Background()

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"username":    "admin_user",
			"private_key": generateTestPrivateKeyPEM(t),
			// account missing
		},
	}
	resp, err := b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "account")
}
