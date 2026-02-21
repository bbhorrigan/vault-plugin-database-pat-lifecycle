// Copyright (c) 2026 Peter Horrigan
// SPDX-License-Identifier: MPL-2.0

package snowflakepat

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathCredentials(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "creds/" + framework.GenericNameRegex("role_name"),

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "snowflake-pat",
			OperationSuffix: "credentials",
		},

		Fields: map[string]*framework.FieldSchema{
			"role_name": {
				Type:        framework.TypeString,
				Description: "Name of the role to generate credentials for.",
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathCredsRead,
				Summary:  "Generate a Snowflake Programmatic Access Token.",
			},
		},

		HelpSynopsis:    "Generate a Snowflake PAT for the given role.",
		HelpDescription: "Generates a Snowflake Programmatic Access Token for the Snowflake user configured in the role. The token is automatically revoked when the Vault lease expires.",
	}
}

func (b *backend) pathCredsRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role_name").(string)

	role, err := getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse("role %q not found", roleName), nil
	}

	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return logical.ErrorResponse("plugin is not configured"), nil
	}

	client, err := newSnowflakeClient(cfg.Account, cfg.Username, cfg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Snowflake: %w", err)
	}
	defer client.Close()

	tokenName := generateTokenName(roleName)

	tokenSecret, err := client.CreatePAT(ctx, role.SnowflakeUser, tokenName, role.RoleRestriction, role.DaysToExpiry)
	if err != nil {
		return nil, fmt.Errorf("failed to create PAT: %w", err)
	}

	ttl := role.TTL
	maxTTL := role.MaxTTL

	resp := b.Secret(secretPATType).Response(
		map[string]interface{}{
			"token_name":     tokenName,
			"token_secret":   tokenSecret,
			"snowflake_user": role.SnowflakeUser,
			"account":        cfg.Account,
		},
		map[string]interface{}{
			"token_name":     tokenName,
			"snowflake_user": role.SnowflakeUser,
			"role_name":      roleName,
		},
	)

	resp.Secret.TTL = ttl
	resp.Secret.MaxTTL = maxTTL

	return resp, nil
}

// generateTokenName creates a unique PAT name safe for Snowflake identifiers.
// Format: vault-<role>-<unix_ts>-<6 random chars>
func generateTokenName(roleName string) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	suffix := make([]byte, 6)
	for i := range suffix {
		suffix[i] = charset[rand.Intn(len(charset))]
	}
	// Truncate role name to keep total length reasonable
	name := roleName
	if len(name) > 20 {
		name = name[:20]
	}
	return fmt.Sprintf("vault-%s-%d-%s", name, time.Now().Unix(), string(suffix))
}
