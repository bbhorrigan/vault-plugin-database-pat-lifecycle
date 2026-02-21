// Copyright (c) 2026 Peter Horrigan
// SPDX-License-Identifier: MPL-2.0

package snowflakepat

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// backendConfig holds the Snowflake admin connection details.
type backendConfig struct {
	Account             string `json:"account"`
	Username            string `json:"username"`
	PrivateKey          []byte `json:"private_key"`
	Database            string `json:"database"`
	DisplayNamePrefix   string `json:"display_name_prefix"`
}

const defaultDisplayNamePrefix = "oidc-"

func pathConfig(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "config",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "snowflake-pat",
		},

		Fields: map[string]*framework.FieldSchema{
			"account": {
				Type:        framework.TypeString,
				Description: "Snowflake account identifier (e.g. myorg-myaccount).",
				Required:    true,
			},
			"username": {
				Type:        framework.TypeString,
				Description: "Snowflake admin username used to create and revoke PATs.",
				Required:    true,
			},
			"private_key": {
				Type:        framework.TypeString,
				Description: "PEM-encoded PKCS8 RSA private key for key-pair authentication.",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Sensitive: true,
				},
			},
			"database": {
				Type:        framework.TypeString,
				Description: "Optional default Snowflake database for the admin connection.",
			},
			"display_name_prefix": {
				Type:        framework.TypeString,
				Description: fmt.Sprintf("Prefix to strip from the Vault token display name to derive the Snowflake username in per-user roles. Defaults to %q, which is correct for the default OIDC auth mount.", defaultDisplayNamePrefix),
				Default:     defaultDisplayNamePrefix,
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathConfigRead,
				Summary:  "Read the current Snowflake connection configuration.",
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
				Summary:  "Configure the Snowflake admin connection.",
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
				Summary:  "Update the Snowflake admin connection configuration.",
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathConfigDelete,
				Summary:  "Delete the Snowflake connection configuration.",
			},
		},

		ExistenceCheck:  b.pathConfigExistenceCheck,
		HelpSynopsis:    "Configure the Snowflake admin connection.",
		HelpDescription: "Configure the Snowflake account, admin user, and key-pair credentials used to create and revoke PATs.",
	}
}

func (b *backend) pathConfigRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return logical.ErrorResponse("not configured"), nil
	}

	prefix := cfg.DisplayNamePrefix
	if prefix == "" {
		prefix = defaultDisplayNamePrefix
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"account":              cfg.Account,
			"username":             cfg.Username,
			"database":             cfg.Database,
			"display_name_prefix":  prefix,
			// private_key intentionally omitted
		},
	}, nil
}

func (b *backend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		cfg = &backendConfig{}
	}

	if v, ok := data.GetOk("account"); ok {
		cfg.Account = v.(string)
	}
	if v, ok := data.GetOk("username"); ok {
		cfg.Username = v.(string)
	}
	if v, ok := data.GetOk("private_key"); ok {
		cfg.PrivateKey = []byte(v.(string))
	}
	if v, ok := data.GetOk("database"); ok {
		cfg.Database = v.(string)
	}
	if v, ok := data.GetOk("display_name_prefix"); ok {
		cfg.DisplayNamePrefix = v.(string)
	}

	if cfg.Account == "" {
		return logical.ErrorResponse("account is required"), nil
	}
	if cfg.Username == "" {
		return logical.ErrorResponse("username is required"), nil
	}
	if len(cfg.PrivateKey) == 0 {
		return logical.ErrorResponse("private_key is required"), nil
	}

	entry, err := logical.StorageEntryJSON(configStoragePath, cfg)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathConfigDelete(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, configStoragePath); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) pathConfigExistenceCheck(ctx context.Context, req *logical.Request, _ *framework.FieldData) (bool, error) {
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return false, err
	}
	return cfg != nil, nil
}

func getConfig(ctx context.Context, s logical.Storage) (*backendConfig, error) {
	entry, err := s.Get(ctx, configStoragePath)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var cfg backendConfig
	if err := entry.DecodeJSON(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}
