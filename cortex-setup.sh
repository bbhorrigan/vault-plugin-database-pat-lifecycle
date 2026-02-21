#!/usr/bin/env bash
# cortex-setup.sh — one-time setup for Vault-backed Snowflake Cortex access
#
# Run this once:
#   chmod +x cortex-setup.sh && ./cortex-setup.sh
#
# After that, use these two commands:
#   cortex-login          → log in with Okta (once per day)
#   cortex                → ask Cortex anything

set -e

VAULT_ADDR_DEFAULT="https://vault.example.com"
SNOWFLAKE_ACCOUNT_DEFAULT="myorg-myaccount"
SNOWFLAKE_USER_DEFAULT=""
VAULT_ROLE_DEFAULT="cortex"
SHELL_RC=""

# ── helpers ────────────────────────────────────────────────────────────────────

green()  { printf '\033[32m%s\033[0m\n' "$*"; }
blue()   { printf '\033[34m%s\033[0m\n' "$*"; }
yellow() { printf '\033[33m%s\033[0m\n' "$*"; }
bold()   { printf '\033[1m%s\033[0m\n' "$*"; }
ask()    { printf '\033[34m%s\033[0m ' "$1"; read -r "$2"; }

# ── intro ──────────────────────────────────────────────────────────────────────

echo ""
bold "  Snowflake Cortex + Vault Setup"
echo "  --------------------------------"
echo "  This script installs the Snowflake CLI and sets up two commands:"
echo ""
echo "    cortex-login   log in with your Okta account (once per day)"
echo "    cortex         ask Cortex anything"
echo ""

# ── gather config ──────────────────────────────────────────────────────────────

ask "Vault address [${VAULT_ADDR_DEFAULT}]:" INPUT_VAULT_ADDR
VAULT_ADDR_VAL="${INPUT_VAULT_ADDR:-$VAULT_ADDR_DEFAULT}"

ask "Snowflake account identifier [${SNOWFLAKE_ACCOUNT_DEFAULT}]:" INPUT_ACCOUNT
SNOWFLAKE_ACCOUNT="${INPUT_ACCOUNT:-$SNOWFLAKE_ACCOUNT_DEFAULT}"

ask "Your Snowflake username (email):" INPUT_USER
SNOWFLAKE_USER="${INPUT_USER:-$SNOWFLAKE_USER_DEFAULT}"

ask "Vault role name [${VAULT_ROLE_DEFAULT}]:" INPUT_ROLE
VAULT_ROLE="${INPUT_ROLE:-$VAULT_ROLE_DEFAULT}"

echo ""

# ── detect shell rc file ───────────────────────────────────────────────────────

if [ -n "$ZSH_VERSION" ] || [ "$(basename "$SHELL")" = "zsh" ]; then
    SHELL_RC="$HOME/.zshrc"
elif [ -n "$BASH_VERSION" ] || [ "$(basename "$SHELL")" = "bash" ]; then
    SHELL_RC="$HOME/.bashrc"
else
    SHELL_RC="$HOME/.profile"
fi

blue "→ Shell config: $SHELL_RC"

# ── install vault cli if needed ────────────────────────────────────────────────

if ! command -v vault &>/dev/null; then
    blue "→ Installing Vault CLI..."
    VAULT_VERSION="1.15.5"
    VAULT_ZIP="vault_${VAULT_VERSION}_linux_amd64.zip"
    curl -fsSL "https://releases.hashicorp.com/vault/${VAULT_VERSION}/${VAULT_ZIP}" -o "/tmp/${VAULT_ZIP}"
    unzip -q "/tmp/${VAULT_ZIP}" -d "$HOME/.local/bin/"
    rm "/tmp/${VAULT_ZIP}"
    green "  ✓ Vault CLI installed"
else
    green "  ✓ Vault CLI already installed ($(vault version | head -1))"
fi

# ── install snowflake cli if needed ───────────────────────────────────────────

if ! command -v snow &>/dev/null && ! [ -f "$HOME/.local/bin/snow" ]; then
    blue "→ Installing Snowflake CLI..."
    if command -v pip3 &>/dev/null; then
        pip3 install --user snowflake-cli --quiet
    elif command -v python3 &>/dev/null; then
        curl -fsSL https://bootstrap.pypa.io/get-pip.py | python3 - --user --break-system-packages -q
        python3 -m pip install --user snowflake-cli --quiet
    else
        echo "Error: Python 3 is required to install the Snowflake CLI."
        exit 1
    fi
    green "  ✓ Snowflake CLI installed"
else
    SNOW_CMD=$(command -v snow || echo "$HOME/.local/bin/snow")
    green "  ✓ Snowflake CLI already installed ($($SNOW_CMD --version))"
fi

SNOW_BIN=$(command -v snow 2>/dev/null || echo "$HOME/.local/bin/snow")

# ── write snowflake connection config ─────────────────────────────────────────

blue "→ Writing Snowflake CLI config..."
mkdir -p "$HOME/.snowflake"
chmod 700 "$HOME/.snowflake"

cat > "$HOME/.snowflake/config.toml" <<TOML
default_connection_name = "vault"

[connections.vault]
account = "${SNOWFLAKE_ACCOUNT}"
user = "${SNOWFLAKE_USER}"
authenticator = "PROGRAMMATIC_ACCESS_TOKEN"
TOML

chmod 600 "$HOME/.snowflake/config.toml"
green "  ✓ Snowflake config written to ~/.snowflake/config.toml"

# ── write shell functions ──────────────────────────────────────────────────────

blue "→ Adding cortex-login and cortex commands to ${SHELL_RC}..."

# Remove any previous install block
if [ -f "$SHELL_RC" ]; then
    # Use a temp file to strip old block
    sed '/# >>> cortex-vault >>>/,/# <<< cortex-vault <<</d' "$SHELL_RC" > "$SHELL_RC.tmp" && mv "$SHELL_RC.tmp" "$SHELL_RC"
fi

cat >> "$SHELL_RC" <<SHELL

# >>> cortex-vault >>>
export VAULT_ADDR="${VAULT_ADDR_VAL}"
export PATH="\$PATH:\$HOME/.local/bin"

# Log in to Vault with Okta — run once per day
cortex-login() {
    vault login -method=oidc
}

# Ask Snowflake Cortex a question
# Usage: cortex "your question here"
#        cortex          (opens interactive prompt)
cortex() {
    # Refresh the Snowflake token from Vault if needed
    if [ -z "\$SNOWFLAKE_CONNECTIONS_VAULT_TOKEN" ] || ! vault token lookup &>/dev/null 2>&1; then
        echo "Getting a fresh Snowflake token from Vault..."
        export SNOWFLAKE_CONNECTIONS_VAULT_TOKEN=\$(vault read -field=token_secret snowflake-pat/creds/${VAULT_ROLE})
    fi

    if [ -z "\$1" ]; then
        # Interactive mode
        echo "Ask Cortex (Ctrl+C to quit):"
        while true; do
            printf '> '
            read -r PROMPT
            [ -z "\$PROMPT" ] && continue
            ${SNOW_BIN} cortex complete --connection vault "\$PROMPT"
            echo ""
        done
    else
        ${SNOW_BIN} cortex complete --connection vault "\$@"
    fi
}
# <<< cortex-vault <<<
SHELL

green "  ✓ Commands added to ${SHELL_RC}"

# ── done ───────────────────────────────────────────────────────────────────────

echo ""
bold "  Setup complete!"
echo ""
echo "  Reload your shell, then:"
echo ""
yellow "    source ${SHELL_RC}"
echo ""
echo "  Then:"
echo ""
yellow "    cortex-login"
echo "    cortex \"What can Snowflake Cortex do?\""
echo ""
