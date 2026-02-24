# Claude Code Instructions

This is a HashiCorp Vault secrets engine plugin that dynamically generates and
revokes Snowflake Programmatic Access Tokens (PATs).

## Project structure

- `backend.go` — plugin factory and path registration
- `path_config.go` — `snowflake-pat/config` endpoint
- `path_roles.go` — `snowflake-pat/roles/<name>` endpoint
- `path_creds.go` — `snowflake-pat/creds/<name>` endpoint (generates PATs)
- `secret_pat.go` — lease renew and revoke callbacks
- `snowflake_client.go` — Snowflake connection and SQL helpers
- `cmd/` — plugin binary entry point

## Rules

- Only change files directly related to the issue or PR. Do not refactor
  surrounding code unless it is the explicit subject of the request.
- Always run `go build ./...` and `go vet ./...` before considering work done.
- Always run `go test ./...` and confirm tests pass.
- Do not hardcode credentials, private keys, or secrets in any file.
- Do not commit to main directly. Always create a new branch and open a PR.
- Keep PR scope tight — one issue, one PR.

## Key design decisions

- The plugin supports two admin auth methods: key-pair (JWT) via `private_key`,
  or Workload Identity Federation (WIF) via `wif_provider`. They are mutually
  exclusive — set exactly one in the config.
- WIF uses `gosnowflake.AuthTypeWorkloadIdentityFederation` with
  `WorkloadIdentityProvider` set to the uppercased provider string (AWS/GCP/AZURE/OIDC).
  gosnowflake fetches attestation tokens from the cloud metadata service at
  connection time — no key material stored in Vault.
- Per-user mode derives the Snowflake username from the caller's Vault entity
  alias (set by OIDC login). Shared mode uses a fixed `snowflake_user` on the
  role.
- Snowflake usernames must be uppercased before double-quoting in SQL because
  Snowflake stores names in uppercase by default and double-quoted identifiers
  are case-sensitive.
- Snowflake enforces a hard limit of 15 PATs per user.

## Running tests

```bash
go test ./...
```

Tests are unit tests with mocked Snowflake — no live Snowflake connection
required.
