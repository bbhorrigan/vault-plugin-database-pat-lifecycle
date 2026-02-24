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

---

### Per-user mode (recommended)

Each developer gets a PAT on **their own Snowflake account**. The Snowflake
username is derived automatically from the developer's Vault identity — no
hardcoded usernames, and each person's PAT limit is independent.

Use this when every developer has their own Snowflake login (the common case
with Okta SSO).

**How it works:**

When a developer logs into Vault via Okta OIDC, Vault creates an entity for
them and records their email as an identity alias. When they request creds, the
plugin looks up that alias to find their Snowflake username. No manual
configuration per developer is required — it happens automatically on first
OIDC login.

```
Developer logs into Vault via Okta
   → Vault entity created, alias name = their email (e.g. peter@example.com)
   → vault read snowflake-pat/creds/cortex
   → Plugin reads alias from entity → gets "peter@example.com"
   → Creates PAT for PETER@EXAMPLE.COM in Snowflake
```

**Setup:**

```bash
# 1. Find your OIDC auth mount accessor
vault auth list -detailed
# Look for the accessor of your oidc mount, e.g. auth_oidc_abc12345

# 2. Set it in the plugin config so the plugin knows which alias to read
vault write snowflake-pat/config \
  account="myorg-myaccount" \
  username="vault_admin" \
  private_key=@/path/to/rsa_key.p8 \
  auth_mount_accessor="auth_oidc_abc12345"

# 3. Create a role with no snowflake_user
vault write snowflake-pat/roles/cortex \
  role_restriction="cortex_role" \
  ttl=1h \
  max_ttl=8h \
  days_to_expiry=1

# 4. Developer requests creds after logging in with Okta
vault read snowflake-pat/creds/cortex
```

Output:
```
Key              Value
---              -----
lease_id         snowflake-pat/creds/cortex/abc123
lease_duration   1h
lease_renewable  true
account          myorg-myaccount
snowflake_user   PETER@EXAMPLE.COM      ← derived from their Okta identity
token_name       vault-cortex-1740000000-abc123
token_secret     <PAT secret>
```

> **Note:** If `auth_mount_accessor` is not set, the plugin falls back to
> picking the first OIDC or JWT alias on the entity. Setting it explicitly is
> recommended to avoid ambiguity if multiple auth methods are enabled.

---

### Shared mode

All users of the role share **one Snowflake service account**. The Snowflake
username is fixed on the role.

Use this for automated pipelines, CI/CD jobs, or any case where a dedicated
service account makes more sense than per-developer accounts.

> **Note:** Snowflake enforces a hard limit of **15 PATs per user**. In shared
> mode this limit is shared across everyone using the role — if 15 leases are
> open at once, new requests will fail until existing leases expire or are
> revoked. The plugin includes a warning in the credential response as a
> reminder. Keep TTLs short so Vault revokes PATs promptly.

**Setup:**

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

Output (note the warning):
```
WARNING! The following warnings were returned from Vault:

  * This role uses a shared Snowflake account. Snowflake enforces a limit of
    15 PATs per user. If the limit is reached, new credential requests will
    fail until existing leases expire or are revoked...

Key              Value
---              -----
lease_id         snowflake-pat/creds/pipeline/abc123
lease_duration   1h
lease_renewable  true
account          myorg-myaccount
snowflake_user   cortex_svc
token_name       vault-pipeline-1740000000-abc123
token_secret     <PAT secret>
```

---

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
  auth_mount_accessor="auth_oidc_abc12345"   # required for per-user mode
```

To find your OIDC mount accessor:

```bash
vault auth list -detailed
# The accessor column for your oidc mount, e.g. auth_oidc_abc12345
```

### 3. Create a role and generate a PAT

See the [Per-user mode](#per-user-mode-recommended) and [Shared mode](#shared-mode)
sections above for role setup and example output.

Use `token_secret` as a Bearer token against any Snowflake REST API:

```bash
curl -X POST \
  -H "Authorization: Bearer <token_secret>" \
  -H "X-Snowflake-Authorization-Token-Type: PROGRAMMATIC_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"model":"snowflake-arctic","messages":[{"role":"user","content":"Hello"}]}' \
  https://myorg-myaccount.snowflakecomputing.com/api/v2/cortex/inference:complete
```

When the Vault lease expires (or `vault lease revoke` is called), the PAT is
automatically removed from Snowflake.

---

## Reference

### Role Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `snowflake_user` | No | — | Snowflake user to create the PAT for. Omit for per-user mode (username derived from Vault identity). Set to a service account for shared mode. |
| `role_restriction` | No | — | Snowflake role to restrict the PAT to |
| `ttl` | No | Engine default | Vault lease duration |
| `max_ttl` | No | Engine default | Maximum renewable Vault lease duration |
| `days_to_expiry` | No | 1 | PAT expiry in Snowflake (1–365 days). Should be >= max_ttl |

### Configuration Parameters

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `account` | Yes | — | Snowflake account identifier (e.g. `myorg-myaccount`) |
| `username` | Yes | — | Admin user with privilege to create PATs for other users |
| `private_key` | See note | — | PEM-encoded PKCS8 RSA private key for key-pair auth. Required unless `wif_provider` is set. |
| `database` | No | — | Default database for the admin connection |
| `auth_mount_accessor` | No | — | Accessor of the Vault auth mount to use when looking up identity aliases in per-user mode (e.g. `auth_oidc_abc12345`). If unset, the plugin picks the first OIDC or JWT alias on the entity. Run `vault auth list -detailed` to find the value. |
| `wif_provider` | See note | — | Cloud provider for Workload Identity Federation auth: `aws`, `gcp`, `azure`, or `oidc`. When set, `private_key` is not required. |
| `wif_entra_resource` | No | — | Azure Entra ID resource URI (Azure WIF only, e.g. `api://my-app-id`). |

> **Note:** Exactly one of `private_key` (key-pair auth) or `wif_provider` (WIF auth) must be set.

---

## Workload Identity Federation (WIF)

WIF lets the plugin authenticate to Snowflake using the cloud provider identity
of the host running Vault — no private key needs to be stored in Vault.

This is ideal when:
- Vault runs on a cloud VM (EC2, Azure VM, GCE) with an attached IAM role or
  Managed Identity
- Vault runs in Kubernetes with a service account projected token
- You want to eliminate long-lived key material from your Vault configuration

**How it works:** Instead of a private key, Vault fetches a short-lived
attestation token from the cloud provider's metadata service (IMDS) and presents
it to Snowflake. Snowflake verifies the token against the trust policy you
configure for the identity.

### Prerequisites in Snowflake

You must configure a trust policy in Snowflake for the identity Vault will use.
See the [Snowflake WIF documentation](https://docs.snowflake.com/en/user-guide/authentication/workload-identity-federation) for full details.

### AWS (EC2 IAM Role / EKS Service Account)

```bash
# Configure with AWS WIF — no private_key needed
vault write snowflake-pat/config \
  account="myorg-myaccount" \
  username="vault_admin" \
  wif_provider="aws"
```

In Snowflake, create a trust policy for the IAM role ARN attached to your Vault EC2 instance or EKS pod.

### GCP (Service Account / Workload Identity)

```bash
vault write snowflake-pat/config \
  account="myorg-myaccount" \
  username="vault_admin" \
  wif_provider="gcp"
```

In Snowflake, create a trust policy for the GCP service account email used by your Vault instance.

### Azure (Managed Identity)

```bash
vault write snowflake-pat/config \
  account="myorg-myaccount" \
  username="vault_admin" \
  wif_provider="azure" \
  wif_entra_resource="api://my-snowflake-app-id"   # optional, app-specific
```

In Snowflake, create a trust policy for the Managed Identity object ID or client ID of your Vault instance.

### Kubernetes (OIDC)

```bash
vault write snowflake-pat/config \
  account="myorg-myaccount" \
  username="vault_admin" \
  wif_provider="oidc"
```

In Snowflake, configure an OIDC trust policy pointing at your Kubernetes OIDC issuer URL.

---

## Developer Authentication

For teams using Okta, developers can authenticate to Vault with their existing
Okta credentials and pull short-lived PATs without any manual Snowflake setup.

See [docs/okta-oidc.md](docs/okta-oidc.md) for a full setup guide.

## License

MPL-2.0
