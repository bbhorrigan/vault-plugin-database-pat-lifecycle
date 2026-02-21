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
<img width="1000" height="700" alt="image" src="https://github.com/user-attachments/assets/9f2d2d0f-8107-4613-b137-4bdb4224f6c7" />

## Authentication

The plugin connects to Snowflake using **key-pair (JWT) authentication** — no
passwords required.

## Modes

The plugin supports two modes, controlled by whether `snowflake_user` is set on
a role.

### Per-user mode (recommended)

Each developer gets a PAT on **their own Snowflake account**. The Snowflake
username is derived automatically from the developer's Vault identity — no
hardcoded usernames, no shared limits.

Use this when every developer has their own Snowflake login (the common case
with Okta SSO).

```bash
# Role — no snowflake_user set
vault write snowflake-pat/roles/cortex \
  role_restriction="cortex_role" \
  ttl=1h \
  max_ttl=8h \
  days_to_expiry=1

# Developer requests creds — gets a PAT for their own account
vault read snowflake-pat/creds/cortex
```

When a developer authenticates to Vault via Okta OIDC and then reads creds,
the plugin strips the auth method prefix (default `oidc-`) from their Vault
token display name to determine their Snowflake username. For example, a
developer who logged in as `peter@example.com` gets a PAT for
`PETER@EXAMPLE.COM` in Snowflake.

### Shared mode

All users of the role share **one Snowflake service account**. The Snowflake
username is fixed on the role.

Use this for automated pipelines, CI/CD jobs, or any case where a dedicated
service account is more appropriate than per-developer accounts.

> **Note:** Snowflake enforces a hard limit of **15 PATs per user**. In shared
> mode this limit is shared across everyone using the role. The plugin will
> include a warning in the credential response as a reminder. Keep TTLs short
> so Vault revokes PATs promptly and stays well under the limit.

```bash
# Role — snowflake_user set to a service account
vault write snowflake-pat/roles/pipeline \
  snowflake_user="cortex_svc" \
  role_restriction="cortex_role" \
  ttl=1h \
  max_ttl=8h \
  days_to_expiry=1

# Any caller gets a PAT for cortex_svc
vault read snowflake-pat/creds/pipeline
```

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
  private_key=@/path/to/rsa_key.p8
```

### 3. Create a role

Per-user (each developer gets a PAT on their own account):

```bash
vault write snowflake-pat/roles/cortex \
  role_restriction="cortex_role" \
  ttl=1h \
  max_ttl=8h \
  days_to_expiry=1
```

Shared (everyone shares a service account):

```bash
vault write snowflake-pat/roles/pipeline \
  snowflake_user="cortex_svc" \
  role_restriction="cortex_role" \
  ttl=1h \
  max_ttl=8h \
  days_to_expiry=1
```

### 4. Generate a PAT

```bash
vault read snowflake-pat/creds/cortex
```

```
Key              Value
---              -----
lease_id         snowflake-pat/creds/cortex/abc123
lease_duration   1h
lease_renewable  true
account          myorg-myaccount
snowflake_user   PETER@EXAMPLE.COM
token_name       vault-cortex-1740000000-abc123
token_secret     <PAT secret>
```

Use `token_secret` as a Bearer token:

```bash
curl -H "Authorization: Bearer <token_secret>" \
  -H "X-Snowflake-Authorization-Token-Type: PROGRAMMATIC_ACCESS_TOKEN" \
  https://myorg-myaccount.snowflakecomputing.com/api/v2/cortex/inference:complete \
  ...
```

When the Vault lease expires (or `vault lease revoke` is called), the PAT is
automatically removed from Snowflake.

## Role Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `snowflake_user` | No | — | Snowflake user to create the PAT for. If omitted, the PAT is created for the requesting user's own account (per-user mode). If set, all callers share this account (shared mode). |
| `role_restriction` | No | — | Snowflake role to restrict the PAT to |
| `ttl` | No | Engine default | Vault lease duration |
| `max_ttl` | No | Engine default | Maximum renewable Vault lease duration |
| `days_to_expiry` | No | 1 | PAT expiry in Snowflake (1–365 days). Should be >= max_ttl |

## Configuration Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `account` | Yes | — | Snowflake account identifier (e.g. `myorg-myaccount`) |
| `username` | Yes | — | Admin user with privilege to create PATs for other users |
| `private_key` | Yes | — | PEM-encoded PKCS8 RSA private key for key-pair auth |
| `database` | No | — | Default database for the admin connection |
| `display_name_prefix` | No | `oidc-` | Prefix stripped from the Vault token display name to derive the Snowflake username in per-user mode. Change this if your OIDC auth method is mounted at a non-default path. |

## Developer Authentication

For teams using Okta, developers can authenticate to Vault with their existing
Okta credentials and pull short-lived PATs without any manual Snowflake setup.

See [docs/okta-oidc.md](docs/okta-oidc.md) for a full setup guide.

## License

MPL-2.0
