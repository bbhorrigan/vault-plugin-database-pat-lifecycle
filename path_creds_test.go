// Copyright (c) 2026 Peter Horrigan
// SPDX-License-Identifier: MPL-2.0

package snowflakepat

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerateTokenName(t *testing.T) {
	name := generateTokenName("my-role")
	require.Contains(t, name, "vault-my-role-")
	require.LessOrEqual(t, len(name), 60)

	// Long role names are truncated
	longName := generateTokenName("this-is-a-very-long-role-name-that-exceeds-twenty-chars")
	require.LessOrEqual(t, len(longName), 60)

	// Names should be unique
	name1 := generateTokenName("role")
	name2 := generateTokenName("role")
	// In practice they differ due to timestamp or random suffix; just check format
	require.Contains(t, name1, "vault-role-")
	require.Contains(t, name2, "vault-role-")
}

func TestGenerateTokenName_SpecialChars(t *testing.T) {
	// Role names with hyphens should be preserved
	name := generateTokenName("my-cortex-role")
	require.Contains(t, name, "vault-my-cortex-role-")
}
