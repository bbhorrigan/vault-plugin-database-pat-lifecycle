# vault-plugin-secrets-snowflakepat

A HashiCorp Vault secrets engine plugin that dynamically generates and revokes
Snowflake [Programmatic Access Tokens (PATs)](https://docs.snowflake.com/en/user-guide/programmatic-access-tokens)
for use with Snowflake Cortex Code and other Snowflake REST APIs.

PATs are automatically revoked when the Vault lease expires.

## Why

Snowflake is deprecating password authentication. Cortex Code and the Snowflake
REST APIs use PATs as Bearer tokens. This plugin provides a Vault-native way to
issue short-lived, automatically-revoked PATs using the same workflow as other
Vault dynamic secrets.

## Authentication

The plugin connects to Snowflake using **key-pair (JWT) authentication** — no
passwords required.

## Setup

### 1. Build and register the plugin

```bash
make build

# Copy to Vault plugin directory
cp bin/vault-plugin-secrets-snowflakepat $VAULT_PLUGIN_DIR/

# Register with Vault
vault plugin register \
  -sha256=$(sha256sum $VAULT_PLUGIN_DIR/vault-plugin-secrets-snowflakepat | cut -d' ' -f1) \
  secret vault-plugin-secrets-snowflakepat

# Enable the secrets engine
vault secrets enable -path=snowflake-pat vault-plugin-secrets-snowflakepat
```

### 2. Configure the admin connection

```bash
vault write snowflake-pat/config \
  account="myorg-myaccount" \
  username="vault_admin" \
  private_key=@/path/to/rsa_key.p8 \
  database="mydb"
```

### 3. Create a role

```bash
vault write snowflake-pat/roles/cortex \
  snowflake_user="cortex_service_user" \
  role_restriction="cortex_role" \
  ttl=1h \
  max_ttl=24h \
  days_to_expiry=1
```

### 4. Generate a PAT

```bash
vault read snowflake-pat/creds/cortex
```

Output:
```
Key              Value
---              -----
lease_id         snowflake-pat/creds/cortex/abc123
lease_duration   1h
lease_renewable  true
token_name       vault-cortex-1740000000-abc123
token_secret     <PAT secret>
snowflake_user   cortex_service_user
account          myorg-myaccount
```

Use the `token_secret` as a Bearer token:
```bash
curl -H "Authorization: Bearer <token_secret>" \
  https://myorg-myaccount.snowflakecomputing.com/api/v2/cortex/inference:complete \
  ...
```

When the Vault lease expires (or `vault lease revoke` is called), the PAT is
automatically removed from Snowflake.

## Role Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `snowflake_user` | Yes | — | Snowflake user to create the PAT for |
| `role_restriction` | No | — | Snowflake role to restrict the PAT to |
| `ttl` | No | Engine default | Vault lease duration |
| `max_ttl` | No | Engine default | Maximum renewable Vault lease duration |
| `days_to_expiry` | No | 1 | PAT expiry in Snowflake (1–365 days). Should be >= max_ttl |

## Configuration Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `account` | Yes | Snowflake account identifier (e.g. `myorg-myaccount`) |
| `username` | Yes | Admin user with privilege to create PATs for other users |
| `private_key` | Yes | PEM-encoded PKCS8 RSA private key for key-pair auth |
| `database` | No | Default database for the admin connection |

## Developer Authentication

For teams using Okta, developers can authenticate to Vault with their existing
Okta credentials and pull short-lived PATs without any manual Snowflake setup.

See [docs/okta-oidc.md](docs/okta-oidc.md) for a full setup guide.

## License

MPL-2.0
