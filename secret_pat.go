// Copyright (c) 2026 Peter Horrigan
// SPDX-License-Identifier: MPL-2.0

package snowflakepat

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func secretPAT(b *backend) *framework.Secret {
	return &framework.Secret{
		Type: secretPATType,

		Fields: map[string]*framework.FieldSchema{
			"token_name": {
				Type:        framework.TypeString,
				Description: "Name of the Snowflake Programmatic Access Token.",
			},
			"token_secret": {
				Type:        framework.TypeString,
				Description: "The PAT secret used as a Bearer token for Snowflake API authentication.",
				DisplayAttrs: &framework.DisplayAttributes{
					Sensitive: true,
				},
			},
			"snowflake_user": {
				Type:        framework.TypeString,
				Description: "Snowflake user the PAT was created for.",
			},
			"account": {
				Type:        framework.TypeString,
				Description: "Snowflake account identifier.",
			},
		},

		Renew:  b.secretPATRenew,
		Revoke: b.secretPATRevoke,
	}
}

// secretPATRenew extends the Vault lease. The PAT itself cannot be extended
// in Snowflake, so this just validates the role still exists and resets TTL.
func (b *backend) secretPATRenew(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	roleName, ok := req.Secret.InternalData["role_name"].(string)
	if !ok {
		return nil, fmt.Errorf("internal data missing role_name")
	}

	role, err := getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, fmt.Errorf("role %q no longer exists — cannot renew", roleName)
	}

	resp := &logical.Response{Secret: req.Secret}
	resp.Secret.TTL = role.TTL
	resp.Secret.MaxTTL = role.MaxTTL

	return resp, nil
}

// secretPATRevoke removes the PAT from Snowflake.
func (b *backend) secretPATRevoke(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	tokenName, ok := req.Secret.InternalData["token_name"].(string)
	if !ok {
		return nil, fmt.Errorf("internal data missing token_name")
	}

	snowflakeUser, ok := req.Secret.InternalData["snowflake_user"].(string)
	if !ok {
		return nil, fmt.Errorf("internal data missing snowflake_user")
	}

	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Snowflake for revocation: %w", err)
	}
	defer client.Close()

	if err := client.RevokePAT(ctx, snowflakeUser, tokenName); err != nil {
		return nil, fmt.Errorf("failed to revoke PAT %q for user %q: %w", tokenName, snowflakeUser, err)
	}

	return nil, nil
}
