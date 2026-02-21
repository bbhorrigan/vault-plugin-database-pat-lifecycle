// Copyright (c) 2026 Peter Horrigan
// SPDX-License-Identifier: MPL-2.0

package snowflakepat

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"
)

func TestRoles_WriteReadDelete(t *testing.T) {
	b, storage := newTestBackend(t)
	ctx := context.Background()

	// Create role
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/my-role",
		Storage:   storage,
		Data: map[string]interface{}{
			"snowflake_user":   "cortex_user",
			"role_restriction": "cortex_role",
			"ttl":              3600,
			"max_ttl":          86400,
			"days_to_expiry":   7,
		},
	}
	resp, err := b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.Nil(t, resp)

	// Read role
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "roles/my-role",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, "cortex_user", resp.Data["snowflake_user"])
	require.Equal(t, "cortex_role", resp.Data["role_restriction"])
	require.Equal(t, float64(3600), resp.Data["ttl"])
	require.Equal(t, float64(86400), resp.Data["max_ttl"])
	require.Equal(t, 7, resp.Data["days_to_expiry"])

	// List roles
	req = &logical.Request{
		Operation: logical.ListOperation,
		Path:      "roles/",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Contains(t, resp.Data["keys"], "my-role")

	// Delete role
	req = &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "roles/my-role",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.Nil(t, resp)

	// Confirm gone
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "roles/my-role",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.Nil(t, resp)
}

func TestRoles_MissingSnowflakeUser(t *testing.T) {
	b, storage := newTestBackend(t)
	ctx := context.Background()

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/bad-role",
		Storage:   storage,
		Data: map[string]interface{}{
			"days_to_expiry": 1,
			// snowflake_user missing
		},
	}
	resp, err := b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "snowflake_user")
}

func TestRoles_InvalidDaysToExpiry(t *testing.T) {
	b, storage := newTestBackend(t)
	ctx := context.Background()

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/bad-role",
		Storage:   storage,
		Data: map[string]interface{}{
			"snowflake_user": "user",
			"days_to_expiry": 400, // > 365
		},
	}
	resp, err := b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.True(t, resp.IsError())
	require.Contains(t, resp.Error().Error(), "days_to_expiry")
}

func TestRoles_DefaultDaysToExpiry(t *testing.T) {
	b, storage := newTestBackend(t)
	ctx := context.Background()

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/default-role",
		Storage:   storage,
		Data: map[string]interface{}{
			"snowflake_user": "user",
		},
	}
	_, err := b.HandleRequest(ctx, req)
	require.NoError(t, err)

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "roles/default-role",
		Storage:   storage,
	}
	resp, err := b.HandleRequest(ctx, req)
	require.NoError(t, err)
	require.Equal(t, defaultDaysToExpiry, resp.Data["days_to_expiry"])
}
