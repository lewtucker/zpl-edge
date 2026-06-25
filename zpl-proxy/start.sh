#!/usr/bin/env bash
set -uo pipefail

# Resolve to zpl-proxy/ regardless of where this script is invoked from
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Find mitmdump — pip installs it in Python's scripts dir, which may not be on PATH
MITMDUMP=$(python3 -c "
import sysconfig, os
p = os.path.join(sysconfig.get_path('scripts'), 'mitmdump')
print(p if os.path.isfile(p) else '')
" 2>/dev/null)

if [ -z "$MITMDUMP" ]; then
    MITMDUMP=$(which mitmdump 2>/dev/null || true)
fi

if [ -z "$MITMDUMP" ] || [ ! -x "$MITMDUMP" ]; then
    echo "Error: mitmdump not found. Install dependencies first:" >&2
    echo "  pip install -e ../zpl-engine && pip install -e ." >&2
    exit 1
fi

mkdir -p data

# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║              ZPL Egress Proxy — Logging Mode                    ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""
echo "This proxy captures all outbound HTTP/HTTPS traffic and logs it."
echo "Nothing is blocked. All requests pass through."
echo ""
echo "── STEP 1: Trust the CA certificate (for HTTPS inspection) ────────"
echo ""
echo "  macOS system-wide (Safari, Chrome):"
echo "    sudo security add-trusted-cert -d -r trustRoot \\"
echo "      -k /Library/Keychains/System.keychain \\"
echo "      ~/.mitmproxy/mitmproxy-ca-cert.pem"
echo ""
echo "  Firefox only (no sudo needed):"
echo "    Settings → Privacy & Security → Certificates → View Certificates"
echo "    → Import → select: ~/.mitmproxy/mitmproxy-ca-cert.pem"
echo ""
echo "  Note: the CA cert is generated on first proxy startup."
echo "        Run this script once, then install the cert, then restart."
echo ""
echo "── STEP 2: Route traffic through the proxy ─────────────────────────"
echo ""
echo "  Option A — Firefox:"
echo "    Settings → General → Network Settings → Manual proxy configuration"
echo "    HTTP Proxy:  localhost    Port: 8080"
echo "    ☑ Also use this proxy for HTTPS"
echo ""
echo "  Option B — macOS system proxy (all apps):"
echo "    System Settings → Network → [your interface] → Details → Proxies"
echo "    ☑ Web Proxy (HTTP)   → localhost:8080"
echo "    ☑ Secure Web Proxy (HTTPS) → localhost:8080"
echo ""
echo "  Option C — terminal / agent process:"
echo "    export HTTP_PROXY=http://localhost:8080"
echo "    export HTTPS_PROXY=http://localhost:8080"
echo "    export SSL_CERT_FILE=~/.mitmproxy/mitmproxy-ca-cert.pem"
echo "    export REQUESTS_CA_BUNDLE=~/.mitmproxy/mitmproxy-ca-cert.pem"
echo ""
echo "── STEP 3: Browse or run your agent ────────────────────────────────"
echo ""
echo "  All traffic will appear below as it flows through the proxy."
echo "  Logs are also written to: data/requests.jsonl"
echo "                        and: data/observations.db (SQLite)"
echo ""
echo "── STEP 4: Shut it down ─────────────────────────────────────────────"
echo ""
echo "  Press Ctrl-C in this terminal."
echo "  The proxy process will be stopped automatically."
echo ""
echo "  Then undo your proxy settings:"
echo ""
echo "  Firefox:"
echo "    Settings → General → Network Settings → No proxy"
echo ""
echo "  macOS system proxy:"
echo "    System Settings → Network → [your interface] → Details → Proxies"
echo "    Uncheck Web Proxy (HTTP) and Secure Web Proxy (HTTPS)"
echo ""
echo "  Terminal / agent process:"
echo "    unset HTTP_PROXY HTTPS_PROXY SSL_CERT_FILE REQUESTS_CA_BUNDLE"
echo ""
echo "  Your captured data remains in:"
echo "    data/requests.jsonl    — full request log (append-only)"
echo "    data/observations.db  — SQLite database with patterns"
echo ""
echo "════════════════════════════════════════════════════════════════════"
echo ""

LOCAL_IP=$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || echo "<this-machine-ip>")

if [ "${1:-}" != "start" ]; then
    echo "Run './start.sh start' to start the proxy."
    echo ""
    exit 0
fi

echo "Starting ZPL proxy on port 8080..."
ulimit -n 65536 2>/dev/null || true
ZPL_CONFIG="$SCRIPT_DIR/config/proxy.yaml" \
"$MITMDUMP" \
    -s src/zpl_proxy/addon.py \
    --listen-port 8080 \
    --quiet &
PROXY_PID=$!

trap "echo ''; echo 'Stopping proxy (PID $PROXY_PID)...'; kill $PROXY_PID 2>/dev/null; exit 0" INT TERM EXIT

# Wait for proxy to start
sleep 2

if ! kill -0 "$PROXY_PID" 2>/dev/null; then
    echo "Error: proxy failed to start." >&2
    exit 1
fi

echo "Proxy running (PID $PROXY_PID)"
echo ""
echo "── Local browser ────────────────────────────────────────────────────"
echo "   HTTP proxy: localhost:8080"
echo "   CA cert:    $HOME/.mitmproxy/mitmproxy-ca-cert.pem"
echo ""
echo "── Remote machines on your network ─────────────────────────────────"
echo "   This machine's IP: $LOCAL_IP"
echo ""
echo "   On OpenClaw / Hermes machine, set:"
echo "     export HTTP_PROXY=http://$LOCAL_IP:8080"
echo "     export HTTPS_PROXY=http://$LOCAL_IP:8080"
echo "     export SSL_CERT_FILE=/path/to/mitmproxy-ca-cert.pem"
echo "     export REQUESTS_CA_BUNDLE=/path/to/mitmproxy-ca-cert.pem"
echo ""
echo "   Copy the CA cert to the remote machine:"
echo "     scp $HOME/.mitmproxy/mitmproxy-ca-cert.pem user@remote-machine:~/"
echo ""
echo "   macOS firewall exception (run once on this machine if needed):"
echo "     sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add $MITMDUMP"
echo "     sudo /usr/libexec/ApplicationFirewall/socketfilterfw --unblockapp $MITMDUMP"
echo ""
echo "Watching for requests (Ctrl-C to stop)..."
echo "────────────────────────────────────────────────────────────────────"

# Wait for the log file to appear (created on first request)
while [ ! -f data/requests.jsonl ]; do
    sleep 0.5
done

tail -f data/requests.jsonl \
    | jq --unbuffered '{ts, agent_id, dest_host, method, path, tool_name, response_code}'
