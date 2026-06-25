# zpl-edge

The **edge components of [MCP Defender](https://mcp-defender.lewtucker.net)** — the pieces that run
out on an agent's machine, packaged on their own so they can be deployed without the Defender's
private control plane.

- **`zpl-engine/`** — the framework-free **ZPL** (Zero Trust Policy Language) engine: compile +
  evaluate. Pure policy logic, no web/proxy dependencies. The single source of truth for ZPL
  matching, shared by the watcher here and by the Defender control plane.
- **`zpl-proxy/`** — the **HTTP egress watcher**: a [mitmproxy](https://mitmproxy.org) process that
  intercepts an agent's outbound HTTP(S), logs/aggregates it, and enforces the ZPL rule set its
  guard delivers from the Defender. Depends on `zpl-engine`. One watcher can front **multiple
  agents** — give each a per-agent proxy URL (`http://<agent>:<token>@host:port`, minted in the
  portal) and the watcher governs + attributes each separately.

A running watcher is bound to a **guard** on an MCP Defender control plane (it pulls its rule set
and pushes logs over an outbound channel). The watcher is useless on its own — it needs a Defender
to register with — but it carries no Defender code.

## Deploy a watcher

Create the HTTP guard in the Defender portal first (that mints the token), then on the agent box:

```bash
curl -fsSL https://raw.githubusercontent.com/lewtucker/zpl-edge/master/zpl-proxy/scripts/install-watcher.sh -o /tmp/install-watcher.sh
bash /tmp/install-watcher.sh \
  --hub-url   https://mcp-defender.lewtucker.net \
  --guard-token <TOKEN>
```

The installer (macOS launchd / Linux systemd) clones this repo, builds a venv, installs
`zpl-engine` then `zpl-proxy`, writes the config, generates the mitmproxy CA, starts the service,
and prints how to point the agent at it (proxy env + trusting the CA in the agent's runtime).

## Develop

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e zpl-engine        # install the engine first (the watcher depends on it)
pip install -e zpl-proxy
PYTHONPATH=zpl-proxy/src python -m pytest zpl-proxy/tests --ignore zpl-proxy/tests/test_analyze.py
```
