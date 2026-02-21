// Copyright (c) 2026 Peter Horrigan
// SPDX-License-Identifier: MPL-2.0

package snowflakepat

import (
	"context"
	"strings"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	configStoragePath = "config"
	rolesStoragePath  = "roles/"
	secretPATType     = "snowflake_pat"
)

// backend is the Vault secrets engine backend for Snowflake PATs.
type backend struct {
	*framework.Backend
	mu sync.RWMutex
}

// Factory creates and configures the backend.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := newBackend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func newBackend() *backend {
	b := &backend{}

	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),

		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				configStoragePath,
			},
		},

		Paths: framework.PathAppend(
			[]*framework.Path{
				pathConfig(b),
				pathCredentials(b),
			},
			pathRoles(b),
		),

		Secrets: []*framework.Secret{
			secretPAT(b),
		},

		BackendType: logical.TypeLogical,

		Invalidate: b.invalidate,
	}

	return b
}

func (b *backend) invalidate(_ context.Context, key string) {
	if key == configStoragePath {
		b.mu.Lock()
		defer b.mu.Unlock()
		// Nothing to invalidate in cache for now; connections are opened per-request.
	}
}

// getClient opens a fresh Snowflake client using the stored config.
func (b *backend) getClient(ctx context.Context, s logical.Storage) (*snowflakeClient, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	cfg, err := getConfig(ctx, s)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, logical.CodedError(400, "plugin is not configured")
	}

	return newSnowflakeClient(cfg.Account, cfg.Username, cfg.PrivateKey)
}

const backendHelp = `
The Snowflake PAT secrets engine dynamically generates Programmatic Access
Tokens (PATs) for Snowflake users. PATs are automatically revoked when the
Vault lease expires.

Configure the engine with the Snowflake account details and an admin user
with key-pair authentication, then create roles that define which Snowflake
user should receive a PAT and for how long.
`
