#!/bin/bash
# setup.sh — VulnScout post-install setup
# Run once after cloning to configure permissions and create .env
#
# Usage: bash setup.sh

set -e

VULNSCOUT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_FILE="/etc/systemd/system/vulnscout-mcp.service"

echo "[*] VulnScout setup starting..."

# -------------------------------------------------------------------
# 1. Create .env from template if it doesn't exist
# -------------------------------------------------------------------
if [ ! -f "$VULNSCOUT_DIR/.env" ]; then
    cp "$VULNSCOUT_DIR/.env.example" "$VULNSCOUT_DIR/.env"
    echo "[+] Created .env from .env.example"
    echo "[!] Edit .env and add your ANTHROPIC_API_KEY and GITHUB_TOKEN before starting the service"
else
    echo "[=] .env already exists, skipping"
fi

# -------------------------------------------------------------------
# 2. Fix ownership of logs and findings directories
# -------------------------------------------------------------------
mkdir -p "$VULNSCOUT_DIR/logs" "$VULNSCOUT_DIR/findings"
chown -R kali:kali "$VULNSCOUT_DIR/logs" "$VULNSCOUT_DIR/findings"
echo "[+] Permissions set on logs/ and findings/"

# -------------------------------------------------------------------
# 3. Install and enable systemd service
# -------------------------------------------------------------------
if [ -f "$VULNSCOUT_DIR/vulnscout-mcp.service" ]; then
    cp "$VULNSCOUT_DIR/vulnscout-mcp.service" "$SERVICE_FILE"
    systemctl daemon-reload
    systemctl enable vulnscout-mcp
    echo "[+] Service installed and enabled"
    echo "[!] Run: sudo systemctl start vulnscout-mcp  (after filling in .env)"
else
    echo "[!] vulnscout-mcp.service not found, skipping service install"
fi

echo ""
echo "[*] Setup complete. Next steps:"
echo "    1. Edit .env:  cat > $VULNSCOUT_DIR/.env << 'EOF'"
echo "       ANTHROPIC_API_KEY=sk-ant-..."
echo "       GITHUB_TOKEN=ghp_..."
echo "       EOF"
echo "    2. Start service:  sudo systemctl start vulnscout-mcp"
echo "    3. Verify:         sudo systemctl show vulnscout-mcp | grep -E 'ANTHROPIC|GITHUB'"
