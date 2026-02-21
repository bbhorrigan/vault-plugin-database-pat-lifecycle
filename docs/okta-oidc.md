# Developer Authentication with Okta OIDC

This guide sets up Okta as the identity provider for Vault so that developers
can authenticate with their existing Okta credentials and retrieve short-lived
Snowflake PATs without ever touching the Snowflake UI.

**End result for developers:**

```bash
# Once per workday — opens a browser, log in with Okta
vault login -method=oidc

# Whenever a Snowflake token is needed
export SNOWFLAKE_TOKEN=$(vault read -field=token_secret snowflake-pat/creds/cortex)
```

---

## Prerequisites

- Vault server already running and initialized
- The `vault-plugin-secrets-snowflakepat` secrets engine already configured
  (see [README](../README.md))
- Okta admin access
- `vault` CLI configured with `VAULT_ADDR` pointing at your Vault server

---

## Step 1 — Create an Okta OIDC Application

1. In the Okta Admin Console, go to **Applications → Applications → Create App Integration**
2. Select **OIDC - OpenID Connect**, then **Web Application**
3. Configure the application:
   - **App integration name:** `HashiCorp Vault`
   - **Grant type:** Authorization Code (checked), Refresh Token (optional)
   - **Sign-in redirect URIs** — add all of these:
     ```
     http://localhost:8250/oidc/callback
     https://vault.example.com/ui/vault/auth/oidc/oidc/callback
     ```
     Replace `vault.example.com` with your Vault server's hostname. The
     `localhost:8250` URI is required for CLI logins from developer machines.
   - **Sign-out redirect URIs:** `https://vault.example.com`
4. Under **Assignments**, assign the app to the Okta groups that should have
   access (e.g. `cortex-users`, `data-platform`)
5. Save and note the **Client ID** and **Client Secret**

---

## Step 2 — Add a Groups Claim to Okta

By default Okta does not include group membership in the OIDC token. You need
to add a claim so Vault can see which groups a user belongs to.

1. Go to **Security → API → Authorization Servers**
2. Click the **default** authorization server (or whichever one your app uses)
3. Go to the **Claims** tab → **Add Claim**
4. Configure the claim:
   - **Name:** `groups`
   - **Include in token type:** ID Token, Always
   - **Value type:** Groups
   - **Filter:** Matches regex `.*`
   - **Include in:** Any scope
5. Save

---

## Step 3 — Configure Vault OIDC Auth

Run these commands against your Vault server. You'll need a Vault token with
admin privileges.

```bash
# Enable the OIDC auth method
vault auth enable oidc

# Configure it with your Okta tenant
vault write auth/oidc/config \
  oidc_discovery_url="https://<your-okta-domain>/oauth2/default" \
  oidc_client_id="<client-id-from-step-1>" \
  oidc_client_secret="<client-secret-from-step-1>" \
  default_role="developer"
```

Replace `<your-okta-domain>` with your Okta domain, e.g. `acme.okta.com`.

---

## Step 4 — Create a Vault Policy

This policy grants read access to PAT credentials. Create one policy per role
or use a wildcard if all Cortex users should access all roles.

```bash
vault policy write snowflake-pat-cortex - <<EOF
# Allow reading PAT credentials for the cortex role
path "snowflake-pat/creds/cortex" {
  capabilities = ["read"]
}
EOF
```

To allow access to multiple roles:

```bash
vault policy write snowflake-pat-all - <<EOF
path "snowflake-pat/creds/*" {
  capabilities = ["read"]
}
EOF
```

---

## Step 5 — Create a Vault OIDC Role

The role maps an Okta group to a Vault policy and sets the session length.

```bash
vault write auth/oidc/role/developer \
  bound_audiences="<client-id-from-step-1>" \
  allowed_redirect_uris="http://localhost:8250/oidc/callback,https://vault.example.com/ui/vault/auth/oidc/oidc/callback" \
  user_claim="email" \
  groups_claim="groups" \
  bound_claims='{"groups":["cortex-users"]}' \
  oidc_scopes="openid,profile,email,groups" \
  policies="snowflake-pat-cortex" \
  ttl=8h
```

Key parameters:

| Parameter | Description |
|-----------|-------------|
| `bound_claims` | Only members of the `cortex-users` Okta group can log in. Change this to match your actual group name. |
| `ttl` | How long the Vault session lasts. `8h` means developers authenticate once per workday. |
| `policies` | The Vault policy granting access to PAT paths. |

If you have multiple teams needing access to different Snowflake roles, create
a Vault OIDC role per team, each bound to a different Okta group and policy.

---

## Step 6 — Developer Setup

Each developer installs the Vault CLI and sets one environment variable,
typically in their shell profile:

```bash
export VAULT_ADDR=https://vault.example.com
```

That's all. No credentials to manage.

---

## Developer Workflow

**Authenticate (once per workday):**

```bash
vault login -method=oidc
# A browser window opens → log in with Okta → browser closes
# Vault token is written to ~/.vault-token, valid for 8h
```

**Get a Snowflake PAT:**

```bash
export SNOWFLAKE_TOKEN=$(vault read -field=token_secret snowflake-pat/creds/cortex)
```

**Use it with the Snowflake CLI or REST API:**

```bash
# Snowflake CLI (snow)
snow cortex complete --token "$SNOWFLAKE_TOKEN" --query "explain this query: ..."

# Or directly against the REST API
curl -X POST \
  -H "Authorization: Bearer $SNOWFLAKE_TOKEN" \
  -H "X-Snowflake-Authorization-Token-Type: PROGRAMMATIC_ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"model":"snowflake-arctic","messages":[{"role":"user","content":"Hello"}]}' \
  "https://<account>.snowflakecomputing.com/api/v2/cortex/inference:complete"
```

The token expires after the configured TTL (default 1 hour) and is
automatically revoked in Snowflake — no cleanup required.

---

## Access Control

Access is managed entirely in Okta:

- **Grant access:** Add the user to the `cortex-users` group in Okta
- **Revoke access:** Remove them from the group — they cannot get new Vault
  tokens at next login. Any tokens already issued expire within TTL.
- **Immediate revocation:** For urgent offboarding, revoke the user's active
  Vault token: `vault token revoke -accessor <accessor>`

To find a user's token accessor:

```bash
vault list auth/token/accessors | xargs -I{} vault token lookup -accessor {}
```

---

## Multiple Teams / Roles

For teams needing access to different Snowflake users or roles, create
additional Vault OIDC roles and policies:

```bash
# Policy for the analytics team
vault policy write snowflake-pat-analytics - <<EOF
path "snowflake-pat/creds/analytics" {
  capabilities = ["read"]
}
EOF

# OIDC role for the analytics Okta group
vault write auth/oidc/role/analytics \
  bound_audiences="<client-id>" \
  allowed_redirect_uris="http://localhost:8250/oidc/callback,https://vault.example.com/ui/vault/auth/oidc/oidc/callback" \
  user_claim="email" \
  groups_claim="groups" \
  bound_claims='{"groups":["analytics-team"]}' \
  oidc_scopes="openid,profile,email,groups" \
  policies="snowflake-pat-analytics" \
  ttl=8h
```

Then create the corresponding Snowflake PAT role:

```bash
vault write snowflake-pat/roles/analytics \
  snowflake_user="analytics_svc" \
  role_restriction="analytics_role" \
  ttl=1h \
  max_ttl=8h \
  days_to_expiry=1
```
