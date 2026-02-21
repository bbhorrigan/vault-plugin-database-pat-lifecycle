// Copyright (c) 2026 Peter Horrigan
// SPDX-License-Identifier: MPL-2.0

package snowflakepat

import (
	"context"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const defaultDaysToExpiry = 1

// patRole defines the template for generating a PAT.
type patRole struct {
	SnowflakeUser   string        `json:"snowflake_user"`
	RoleRestriction string        `json:"role_restriction"`
	TTL             time.Duration `json:"ttl"`
	MaxTTL          time.Duration `json:"max_ttl"`
	DaysToExpiry    int           `json:"days_to_expiry"`
}

func pathRoles(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: rolesStoragePath + framework.GenericNameRegex("role_name"),

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "snowflake-pat",
				Name:            "role",
			},

			Fields: map[string]*framework.FieldSchema{
				"role_name": {
					Type:        framework.TypeString,
					Description: "Name of the role.",
				},
				"snowflake_user": {
					Type:        framework.TypeString,
					Description: "Snowflake user for whom the PAT will be created. If omitted, the PAT is created for the requesting user derived from their Vault identity (per-user mode). If set, all users of this role share one Snowflake account (shared mode) — note Snowflake enforces a limit of 15 PATs per user.",
				},
				"role_restriction": {
					Type:        framework.TypeString,
					Description: "Optional Snowflake role restriction applied to the generated PAT.",
				},
				"ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Duration of the Vault lease for generated PATs. Defaults to the engine default TTL.",
				},
				"max_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Maximum duration of the Vault lease for generated PATs.",
				},
				"days_to_expiry": {
					Type:        framework.TypeInt,
					Description: "Number of days until the PAT expires in Snowflake (1-365). Defaults to 1.",
					Default:     defaultDaysToExpiry,
				},
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathRoleRead,
					Summary:  "Read a PAT role.",
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathRoleWrite,
					Summary:  "Create a PAT role.",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathRoleWrite,
					Summary:  "Update a PAT role.",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathRoleDelete,
					Summary:  "Delete a PAT role.",
				},
			},

			ExistenceCheck:  b.pathRoleExistenceCheck,
			HelpSynopsis:    "Manage Snowflake PAT roles.",
			HelpDescription: "Create roles that define which Snowflake user gets a PAT, role restrictions, and TTL settings.",
		},
		{
			Pattern: rolesStoragePath + "?$",

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "snowflake-pat",
				Name:            "roles",
			},

			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathRoleList,
					Summary:  "List configured PAT roles.",
				},
			},

			HelpSynopsis: "List configured PAT roles.",
		},
	}
}

func (b *backend) pathRoleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role_name").(string)

	role, err := getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"snowflake_user":   role.SnowflakeUser,
			"role_restriction": role.RoleRestriction,
			"ttl":              role.TTL.Seconds(),
			"max_ttl":          role.MaxTTL.Seconds(),
			"days_to_expiry":   role.DaysToExpiry,
		},
	}, nil
}

func (b *backend) pathRoleWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role_name").(string)

	role, err := getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		role = &patRole{DaysToExpiry: defaultDaysToExpiry}
	}

	if v, ok := data.GetOk("snowflake_user"); ok {
		role.SnowflakeUser = v.(string)
	}
	if v, ok := data.GetOk("role_restriction"); ok {
		role.RoleRestriction = v.(string)
	}
	if v, ok := data.GetOk("ttl"); ok {
		role.TTL = time.Duration(v.(int)) * time.Second
	}
	if v, ok := data.GetOk("max_ttl"); ok {
		role.MaxTTL = time.Duration(v.(int)) * time.Second
	}
	if v, ok := data.GetOk("days_to_expiry"); ok {
		role.DaysToExpiry = v.(int)
	}

	if role.DaysToExpiry < 1 || role.DaysToExpiry > 365 {
		return logical.ErrorResponse("days_to_expiry must be between 1 and 365"), nil
	}

	entry, err := logical.StorageEntryJSON(rolesStoragePath+roleName, role)
	if err != nil {
		return nil, err
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathRoleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role_name").(string)

	if err := req.Storage.Delete(ctx, rolesStoragePath+roleName); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathRoleList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	roles, err := req.Storage.List(ctx, rolesStoragePath)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(roles), nil
}

func (b *backend) pathRoleExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	roleName := data.Get("role_name").(string)
	role, err := getRole(ctx, req.Storage, roleName)
	if err != nil {
		return false, err
	}
	return role != nil, nil
}

func getRole(ctx context.Context, s logical.Storage, name string) (*patRole, error) {
	entry, err := s.Get(ctx, rolesStoragePath+name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var role patRole
	if err := entry.DecodeJSON(&role); err != nil {
		return nil, err
	}

	return &role, nil
}
