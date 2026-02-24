// Copyright (c) 2026 Peter Horrigan
// SPDX-License-Identifier: MPL-2.0

package snowflakepat

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"
	"net/url"
	"strings"

	"github.com/snowflakedb/gosnowflake"
)

// snowflakeClient wraps a Snowflake SQL connection for PAT operations.
type snowflakeClient struct {
	db      *sql.DB
	account string
}

// newSnowflakeClientFromConfig opens a Snowflake connection using the auth method
// configured in cfg. Uses WIF when cfg.WIFProvider is set, otherwise uses key-pair auth.
func newSnowflakeClientFromConfig(cfg *backendConfig) (*snowflakeClient, error) {
	if cfg.WIFProvider != "" {
		return newSnowflakeClientWIF(cfg.Account, cfg.Username, cfg.WIFProvider, cfg.WIFEntraResource)
	}
	return newSnowflakeClient(cfg.Account, cfg.Username, cfg.PrivateKey)
}

// newSnowflakeClientWIF opens a Snowflake connection using Workload Identity
// Federation (WIF). The cloud provider's native identity is used — no private
// key is needed. wifProvider must be one of: aws, gcp, azure, oidc.
func newSnowflakeClientWIF(account, username, wifProvider, wifEntraResource string) (*snowflakeClient, error) {
	dsn := fmt.Sprintf("%s:@%s.snowflakecomputing.com?authenticator=WORKLOAD_IDENTITY", username, account)
	cfg, err := gosnowflake.ParseDSN(dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DSN: %w", err)
	}

	cfg.WorkloadIdentityProvider = strings.ToUpper(wifProvider)
	if wifEntraResource != "" {
		cfg.WorkloadIdentityEntraResource = wifEntraResource
	}

	connector := gosnowflake.NewConnector(gosnowflake.SnowflakeDriver{}, *cfg)
	db := sql.OpenDB(connector)

	return &snowflakeClient{db: db, account: account}, nil
}

// newSnowflakeClient opens a Snowflake connection using key-pair (JWT) auth.
// account should be the bare account identifier (e.g. "sfseeurope-sfcto_jberkowsky").
// username is the Snowflake user to connect as.
// privateKeyPEM is the PEM-encoded PKCS8 RSA private key.
func newSnowflakeClient(account, username string, privateKeyPEM []byte) (*snowflakeClient, error) {
	privateKey, err := parsePrivateKey(privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	connURL := fmt.Sprintf("%s.snowflakecomputing.com", account)

	u, err := url.Parse(connURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse connection URL: %w", err)
	}

	q := u.Query()
	q.Set("authenticator", gosnowflake.AuthTypeJwt.String())
	u.RawQuery = q.Encode()

	dsn := fmt.Sprintf("%s:@%s", username, u.String())
	cfg, err := gosnowflake.ParseDSN(dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DSN: %w", err)
	}
	cfg.PrivateKey = privateKey

	connector := gosnowflake.NewConnector(gosnowflake.SnowflakeDriver{}, *cfg)
	db := sql.OpenDB(connector)

	return &snowflakeClient{db: db, account: account}, nil
}

// Close closes the underlying database connection.
func (c *snowflakeClient) Close() error {
	return c.db.Close()
}

// Ping verifies the connection is alive.
func (c *snowflakeClient) Ping(ctx context.Context) error {
	return c.db.PingContext(ctx)
}

// CreatePAT creates a Programmatic Access Token for the given Snowflake user.
// Returns the token secret, which is only available at creation time.
func (c *snowflakeClient) CreatePAT(ctx context.Context, snowflakeUser, tokenName, roleRestriction string, daysToExpiry int) (string, error) {
	query := fmt.Sprintf(
		"ALTER USER %s ADD PROGRAMMATIC ACCESS TOKEN %s DAYS_TO_EXPIRY = %d",
		snowflakeQuoteUser(snowflakeUser),
		snowflakeQuoteIdent(tokenName),
		daysToExpiry,
	)

	if roleRestriction != "" {
		query += fmt.Sprintf(" ROLE_RESTRICTION = '%s'", roleRestriction)
	}

	rows, err := c.db.QueryContext(ctx, query)
	if err != nil {
		return "", fmt.Errorf("failed to create PAT: %w", err)
	}
	defer rows.Close()

	// The result has two columns: token_name, token_secret
	if !rows.Next() {
		return "", fmt.Errorf("no result returned from ADD PROGRAMMATIC ACCESS TOKEN")
	}

	var retTokenName, tokenSecret string
	if err := rows.Scan(&retTokenName, &tokenSecret); err != nil {
		return "", fmt.Errorf("failed to scan PAT result: %w", err)
	}

	if err := rows.Err(); err != nil {
		return "", fmt.Errorf("error reading PAT result: %w", err)
	}

	return tokenSecret, nil
}

// RevokePAT removes a Programmatic Access Token for the given Snowflake user.
func (c *snowflakeClient) RevokePAT(ctx context.Context, snowflakeUser, tokenName string) error {
	query := fmt.Sprintf(
		"ALTER USER %s REMOVE PROGRAMMATIC ACCESS TOKEN %s",
		snowflakeQuoteUser(snowflakeUser),
		snowflakeQuoteIdent(tokenName),
	)

	_, err := c.db.ExecContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to revoke PAT: %w", err)
	}

	return nil
}

// parsePrivateKey parses a PEM-encoded PKCS8 RSA private key.
func parsePrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("unexpected key type %q, expected \"PRIVATE KEY\"", block.Type)
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS8 private key: %w", err)
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not an RSA key")
	}

	return rsaKey, nil
}

// snowflakeQuoteIdent double-quotes a Snowflake identifier.
func snowflakeQuoteIdent(name string) string {
	return fmt.Sprintf(`"%s"`, name)
}

// snowflakeQuoteUser double-quotes a Snowflake user identifier, uppercasing it
// first. Snowflake stores usernames in uppercase by default; double-quoting is
// case-sensitive, so we must uppercase to match the stored name.
func snowflakeQuoteUser(name string) string {
	return fmt.Sprintf(`"%s"`, strings.ToUpper(name))
}
