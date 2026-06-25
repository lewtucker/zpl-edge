#!/usr/bin/env bash
# install-watcher.sh — one-command deploy of the MCP Defender HTTP egress watcher.
#
# Sets up the mitmproxy-based watcher and binds it to a Defender guard:
#   clone/refresh the repo · venv + install (zpl-engine THEN zpl-proxy) · write
#   config/proxy.local.yaml · generate the mitmproxy CA · install + start the
#   service (macOS launchd / Linux systemd) · print how to point the agent at it.
#
# Idempotent: re-run to update the token, repo, or service.
#
# PREREQ: create the HTTP guard in the portal first (that mints the token).
#
# Usage:
#   install-watcher.sh --hub-url https://mcp-defender.lewtucker.net \
#                      --guard-token <token> [--port 8080] [--repo-dir ~/zpl-edge]
#
# The token is a secret: pass it on the CLI (or via ZPL_HUB_GUARD_TOKEN) — it is
# written to config/proxy.local.yaml (chmod 600, gitignored) and never echoed.
set -euo pipefail

# ── defaults ────────────────────────────────────────────────────────────────
REPO_DIR="${ZPL_REPO_DIR:-$HOME/zpl-edge}"
GIT_URL="${ZPL_GIT_URL:-https://github.com/lewtucker/zpl-edge.git}"
LISTEN_HOST="127.0.0.1"
LISTEN_PORT="8080"
LABEL="net.lewtucker.zpl-watcher"     # macOS launchd label / Linux systemd unit name
PYTHON="${PYTHON:-python3}"
HUB_URL="${ZPL_HUB_URL:-}"
GUARD_TOKEN="${ZPL_HUB_GUARD_TOKEN:-}"

usage() { sed -n '2,30p' "$0"; exit "${1:-0}"; }

# ── args ─────────────────────────────────────────────────────────────────────
while [ $# -gt 0 ]; do
  case "$1" in
    --hub-url)      HUB_URL="$2"; shift 2 ;;
    --guard-token)  GUARD_TOKEN="$2"; shift 2 ;;
    --port)         LISTEN_PORT="$2"; shift 2 ;;
    --listen-host)  LISTEN_HOST="$2"; shift 2 ;;
    --repo-dir)     REPO_DIR="$2"; shift 2 ;;
    --git-url)      GIT_URL="$2"; shift 2 ;;
    --python)       PYTHON="$2"; shift 2 ;;
    --label)        LABEL="$2"; shift 2 ;;
    -h|--help)      usage 0 ;;
    *) echo "unknown arg: $1" >&2; usage 1 ;;
  esac
done
[ -n "$HUB_URL" ]     || { echo "ERROR: --hub-url is required" >&2; exit 1; }
[ -n "$GUARD_TOKEN" ] || { echo "ERROR: --guard-token is required (create the guard in the portal first)" >&2; exit 1; }

OS="$(uname -s)"
say() { printf '\n\033[1m▶ %s\033[0m\n' "$*"; }

# ── 1. repo (zpl-edge: zpl-proxy + its sibling zpl-engine) ────────────────────
say "Repo at $REPO_DIR"
if [ -d "$REPO_DIR/.git" ]; then
  git -C "$REPO_DIR" pull --ff-only || echo "  (pull skipped — keeping current checkout)"
elif [ -d "$REPO_DIR/zpl-proxy" ] && [ -d "$REPO_DIR/zpl-engine" ]; then
  echo "  (existing non-git tree — using as-is)"
else
  git clone --depth 1 "$GIT_URL" "$REPO_DIR"   # the edge repo is just zpl-engine + zpl-proxy
fi
PROXY_DIR="$REPO_DIR/zpl-proxy"
ENGINE_DIR="$REPO_DIR/zpl-engine"
[ -d "$ENGINE_DIR" ] || { echo "ERROR: $ENGINE_DIR missing — need the zpl-edge repo (zpl-proxy depends on zpl-engine)" >&2; exit 1; }
VENV="$PROXY_DIR/.venv"

# ── 2. venv + install (engine FIRST so the app's dependency resolves) ─────────
say "Python env + install"
[ -d "$VENV" ] || "$PYTHON" -m venv "$VENV"
"$VENV/bin/pip" install -q --upgrade pip
"$VENV/bin/pip" install -q -e "$ENGINE_DIR"
"$VENV/bin/pip" install -q -e "$PROXY_DIR"

# ── 3. config (proxy.local.yaml overlays the base proxy.yaml; see config.py) ──
say "Config → $PROXY_DIR/config/proxy.local.yaml"
mkdir -p "$PROXY_DIR/config" "$PROXY_DIR/data"
umask 077
cat > "$PROXY_DIR/config/proxy.local.yaml" <<EOF
# Machine-specific watcher settings (gitignored). Written by install-watcher.sh.
hub_url: $HUB_URL
hub_guard_token: $GUARD_TOKEN
listen_host: $LISTEN_HOST
listen_port: $LISTEN_PORT

# Enforcement MODE (monitor/flag/enforce) + the rule set are set on the GUARD in
# the portal and delivered via the bundle — not here.

# Long-poll / token-bearing hosts to tunnel raw (never intercept). Appends to base.
ignore_hosts:
  - 'api\.telegram\.org'
EOF
chmod 600 "$PROXY_DIR/config/proxy.local.yaml"
umask 022

# ── 4. mitmproxy CA (generated on first run) ──────────────────────────────────
CERT="$HOME/.mitmproxy/mitmproxy-ca-cert.pem"
if [ ! -f "$CERT" ]; then
  say "Generating mitmproxy CA"
  ( "$VENV/bin/mitmdump" --listen-host 127.0.0.1 --listen-port "$LISTEN_PORT" >/dev/null 2>&1 & \
    pid=$!; sleep 4; kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true )
fi

# ── 5. service ────────────────────────────────────────────────────────────────
MITM="$VENV/bin/mitmdump"
ADDON="$PROXY_DIR/src/zpl_proxy/addon.py"
CFG="$PROXY_DIR/config/proxy.yaml"   # ZPL_CONFIG → base; proxy.local.yaml auto-overlays
LOG="$PROXY_DIR/data/watcher.log"

if [ "$OS" = "Darwin" ]; then
  say "launchd service ($LABEL)"
  PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
  mkdir -p "$HOME/Library/LaunchAgents"
  cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>$MITM</string>
    <string>-s</string><string>$ADDON</string>
    <string>--listen-host</string><string>$LISTEN_HOST</string>
    <string>--listen-port</string><string>$LISTEN_PORT</string>
    <string>--quiet</string>
  </array>
  <key>EnvironmentVariables</key><dict><key>ZPL_CONFIG</key><string>$CFG</string></dict>
  <key>WorkingDirectory</key><string>$PROXY_DIR</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>$LOG</string>
  <key>StandardErrorPath</key><string>$LOG</string>
</dict>
</plist>
EOF
  launchctl bootout "gui/$(id -u)/$LABEL" 2>/dev/null || true
  launchctl bootstrap "gui/$(id -u)" "$PLIST"
  launchctl kickstart -k "gui/$(id -u)/$LABEL"
  VIEW_LOG="tail -f $LOG"
elif [ "$OS" = "Linux" ]; then
  say "systemd service ($LABEL) — needs sudo"
  UNIT="/etc/systemd/system/$LABEL.service"
  sudo tee "$UNIT" >/dev/null <<EOF
[Unit]
Description=MCP Defender HTTP egress watcher
After=network.target

[Service]
Type=simple
User=$(id -un)
WorkingDirectory=$PROXY_DIR
Environment=ZPL_CONFIG=$CFG
ExecStart=$MITM -s $ADDON --listen-host $LISTEN_HOST --listen-port $LISTEN_PORT --quiet
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
  sudo systemctl daemon-reload
  sudo systemctl enable --now "$LABEL"
  sudo systemctl restart "$LABEL"
  VIEW_LOG="journalctl -u $LABEL -f"
else
  echo "ERROR: unsupported OS '$OS' (need Darwin or Linux)" >&2; exit 1
fi

# ── 6. verify + how to point the agent ───────────────────────────────────────
say "Verifying hub connection (look for watcher_bundle_applied)"
sleep 8
if [ "$OS" = "Darwin" ]; then RECENT="$(tail -n 25 "$LOG" 2>/dev/null)"; else RECENT="$(journalctl -u "$LABEL" -n 25 --no-pager 2>/dev/null)"; fi
echo "$RECENT" | grep -E "watcher_bundle_applied|watcher_registered|watcher_.*rejected|status=401" || echo "  (no hub events yet — check the log)"
if echo "$RECENT" | grep -q "status=401"; then
  echo "  ⚠ 401 — the guard token is rejected by the hub. Re-check --guard-token / --hub-url."
fi

cat <<EOF

────────────────────────────────────────────────────────────────────────────
Watcher is up on $LISTEN_HOST:$LISTEN_PORT. Logs:  $VIEW_LOG

Point your agent at it (and trust the CA so HTTPS is intercepted):

  CA cert:  $CERT
  HTTP_PROXY=http://$LISTEN_HOST:$LISTEN_PORT
  HTTPS_PROXY=http://$LISTEN_HOST:$LISTEN_PORT
  NO_PROXY=api.telegram.org,.telegram.org      # long-poll/token hosts to bypass

  Node agents (OpenClaw):   NODE_EXTRA_CA_CERTS=$CERT
  Python agents:            REQUESTS_CA_BUNDLE=$CERT   (also SSL_CERT_FILE=$CERT)

The agent's runtime usually does NOT read the OS keychain — set the env var above
for its language. Then restart the agent and confirm requests appear in the log.

Enforcement: bind a rule set to this guard in the portal and set its mode to
flag/enforce. The watcher swaps the bundle within ~5s — no restart needed.
────────────────────────────────────────────────────────────────────────────
EOF
