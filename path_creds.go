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

	// Determine the target Snowflake user.
	//
	// Shared mode: snowflake_user is set on the role — all callers create PATs
	// for that one account. Snowflake enforces a 15-PAT limit per user.
	//
	// Per-user mode: snowflake_user is empty — each caller gets a PAT for their
	// own Snowflake account, derived from their Vault entity alias name (the
	// value of user_claim from OIDC, typically their email address).
	snowflakeUser := role.SnowflakeUser
	shared := snowflakeUser != ""

	if !shared {
		if req.EntityID == "" {
			return logical.ErrorResponse(
				"per-user mode requires the caller to have a Vault entity — " +
					"log in via OIDC or another identity-aware auth method, " +
					"or set snowflake_user on the role to use shared mode",
			), nil
		}
		entity, err := b.System().EntityInfo(req.EntityID)
		if err != nil {
			return nil, fmt.Errorf("failed to look up Vault entity: %w", err)
		}
		if entity == nil {
			return logical.ErrorResponse("no Vault entity found for entity ID %q", req.EntityID), nil
		}
		snowflakeUser, err = snowflakeUsernameFromEntity(entity, cfg.AuthMountAccessor)
		if err != nil {
			return logical.ErrorResponse("%s", err.Error()), nil
		}
	}

	client, err := newSnowflakeClientFromConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Snowflake: %w", err)
	}
	defer client.Close()

	tokenName := generateTokenName(roleName)

	tokenSecret, err := client.CreatePAT(ctx, snowflakeUser, tokenName, role.RoleRestriction, role.DaysToExpiry)
	if err != nil {
		return nil, fmt.Errorf("failed to create PAT: %w", err)
	}

	ttl := role.TTL
	maxTTL := role.MaxTTL

	resp := b.Secret(secretPATType).Response(
		map[string]interface{}{
			"token_name":     tokenName,
			"token_secret":   tokenSecret,
			"snowflake_user": snowflakeUser,
			"account":        cfg.Account,
		},
		map[string]interface{}{
			"token_name":     tokenName,
			"snowflake_user": snowflakeUser,
			"role_name":      roleName,
		},
	)

	resp.Secret.TTL = ttl
	resp.Secret.MaxTTL = maxTTL

	if shared {
		resp.AddWarning(
			"This role uses a shared Snowflake account. Snowflake enforces a limit of 15 PATs " +
				"per user. If the limit is reached, new credential requests will fail until " +
				"existing leases expire or are revoked. Consider using per-user mode (omit " +
				"snowflake_user from the role) if each developer has their own Snowflake account.",
		)
	}

	return resp, nil
}

// snowflakeUsernameFromEntity extracts the Snowflake username from a Vault
// entity by looking at its identity aliases. The alias name is the value of
// the user_claim from OIDC (typically the user's email address).
//
// If mountAccessor is set, only the alias from that specific auth mount is
// considered. Otherwise the first OIDC or JWT alias is used.
func snowflakeUsernameFromEntity(entity *logical.Entity, mountAccessor string) (string, error) {
	if mountAccessor != "" {
		for _, alias := range entity.Aliases {
			if alias.MountAccessor == mountAccessor {
				return alias.Name, nil
			}
		}
		return "", fmt.Errorf(
			"no identity alias found for auth mount accessor %q — "+
				"run `vault auth list -detailed` to verify the accessor and update auth_mount_accessor in the plugin config",
			mountAccessor,
		)
	}

	// No accessor configured — use the first OIDC or JWT alias.
	for _, alias := range entity.Aliases {
		if alias.MountType == "oidc" || alias.MountType == "jwt" {
			return alias.Name, nil
		}
	}

	return "", fmt.Errorf(
		"no OIDC or JWT identity alias found on Vault entity — " +
			"log in via an OIDC auth method, or set auth_mount_accessor in the plugin config, " +
			"or set snowflake_user on the role to use shared mode",
	)
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
