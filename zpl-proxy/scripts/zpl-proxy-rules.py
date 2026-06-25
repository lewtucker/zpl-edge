#!/usr/bin/env python3
"""
analyze.py — Generate a ZPL policy document from observed proxy traffic.

Reads the patterns table from observations.db, clusters hosts into named
service classes, and emits a complete ZPL document with Define, Declare, and
Allow statements that can be loaded directly by the proxy in enforce mode.

Usage:
    python scripts/analyze.py                        # stdout, min 1 observation
    python scripts/analyze.py --min-count 3          # only well-established patterns
    python scripts/analyze.py --output rules.zpl     # write to file
    python scripts/analyze.py --include-unknown      # include unresolved agents as *
    python scripts/analyze.py --compact              # collapse read+write → access
"""
from __future__ import annotations

import argparse
import json
import re
import sqlite3
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

_SCRIPTS_DIR = Path(__file__).parent
_PROXY_ROOT = _SCRIPTS_DIR.parent
sys.path.insert(0, str(_PROXY_ROOT / "src"))

from zpl_proxy.config import load_config

# ── Verb mapping ──────────────────────────────────────────────────────────────

_HTTP_VERB_MAP = {
    "GET":    "read",
    "HEAD":   "read",
    "POST":   "write",
    "PUT":    "write",
    "PATCH":  "write",
    "DELETE": "operate",
}

# ── Host → service class naming ───────────────────────────────────────────────

# TLDs we strip to find the "interesting" part of a hostname.
_TLDS = {
    "com", "io", "ai", "org", "net", "dev", "edu", "gov",
    "co", "uk", "us", "eu", "de", "fr", "jp", "au", "cloud",
    "app", "info", "biz", "tech", "software",
}
# Subdomain prefixes that carry no semantic value — strip them to find the SLD.
_NOISE_PREFIXES = {
    "api", "www", "cdn", "static", "assets", "app", "raw",
    "docs", "s3", "storage", "media", "img", "images",
}


def _sld(host: str) -> str:
    """Return the second-level domain (registered domain base) of a hostname.

    "api.anthropic.com" → "anthropic"
    "gitlab.appliedinvention.com" → "appliedinvention"
    "192.168.1.1" → "192.168.1.1"   (IP addresses returned as-is)
    """
    # IP addresses
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
        return host

    parts = host.lower().split(".")
    # Strip common TLDs from the right (handle .co.uk etc. naively)
    while len(parts) > 1 and parts[-1] in _TLDS:
        parts.pop()
    # What remains: ["api", "anthropic"] or ["gitlab", "appliedinvention"] etc.
    if not parts:
        return host
    # The last part is now the SLD
    return parts[-1]


def _class_name(sld: str) -> str:
    """Turn an SLD into a ZPL class name.

    "anthropic"         → "AnthropicAPI"
    "appliedinvention"  → "AppliedinventionAPI"
    "applied-invention" → "AppliedInventionAPI"
    """
    # Split on hyphens/underscores so "applied-invention" → "AppliedInvention"
    words = re.split(r"[-_]", sld)
    name = "".join(w.title() for w in words if w)
    return (name or "Unknown") + "API"


def host_to_class(host: str) -> str:
    return _class_name(_sld(host))


# ── Path generalization ───────────────────────────────────────────────────────

_UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I
)
_NUM_SEGMENT_RE = re.compile(r"(?<=/)\d{2,}(?=/|$)")
_HEX_SEGMENT_RE = re.compile(r"(?<=/)[0-9a-f]{16,}(?=/|$)", re.I)


def generalize_path(path: str | None) -> str | None:
    """Collapse variable path segments to * so similar paths merge."""
    if not path:
        return path
    path = _UUID_RE.sub("*", path)
    path = _NUM_SEGMENT_RE.sub("*", path)
    path = _HEX_SEGMENT_RE.sub("*", path)
    return path


# ── Rule key ──────────────────────────────────────────────────────────────────

# Each unique (agent, host, verb) triple becomes one ZPL Allow rule.
# Keeping the triple compact means a typical dataset produces well under 100
# rules (usually: #agents × #hosts × 2–3 verbs).


def _pattern_verb(method: str | None, tool_name: str | None) -> str:
    """Determine the ZPL verb for a pattern row."""
    if tool_name:
        return "use"
    return _HTTP_VERB_MAP.get((method or "").upper(), "access")


# ── Core generation ───────────────────────────────────────────────────────────

def generate(
    db_path: Path,
    min_count: int,
    include_unknown: bool,
    compact: bool,
    redact_rules,
) -> dict:
    """Read patterns and return all data needed to render a ZPL document.

    Returns a dict with keys:
      stats:         {total_patterns, total_observations, agent_count, host_count}
      class_map:     {host → class_name}        (sorted by class then host)
      agents:        [agent_id, ...]             (named agents only)
      rules:         [(agent_label, verb, class_name, host, pattern_ids, count)]
    """
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row

    rows = conn.execute(
        "SELECT * FROM patterns WHERE count >= ? ORDER BY agent_id, dest_host, method",
        (min_count,),
    ).fetchall()
    conn.close()

    # ── Build host → class map ────────────────────────────────────────────────
    hosts_seen: set[str] = set()
    for row in rows:
        if row["dest_host"]:
            hosts_seen.add(row["dest_host"])

    # Group hosts by SLD so subdomains share a class name
    sld_to_hosts: dict[str, list[str]] = defaultdict(list)
    for host in sorted(hosts_seen):
        sld_to_hosts[_sld(host)].append(host)

    class_map: dict[str, str] = {}  # host → class_name
    for sld, hosts in sld_to_hosts.items():
        cn = _class_name(sld)
        for host in hosts:
            class_map[host] = cn

    # ── Accumulate rules: (agent_label, verb) per host ────────────────────────
    # rule_key: (agent_label, host, verb) → (pattern_ids, total_count)
    rule_acc: dict[tuple, tuple[list, int]] = {}

    named_agents: set[str] = set()

    for row in rows:
        agent_id = row["agent_id"] or "unknown"
        host = row["dest_host"]
        method = row["method"]
        tool_name = row["tool_name"]
        count = row["count"]
        pattern_id = row["id"]

        if agent_id == "unknown":
            if not include_unknown:
                continue
            agent_label = "*"
        else:
            named_agents.add(agent_id)
            agent_label = agent_id

        verb = _pattern_verb(method, tool_name)
        key = (agent_label, host, verb)

        ids, total = rule_acc.get(key, ([], 0))
        ids.append(pattern_id)
        rule_acc[key] = (ids, total + count)

    # ── Optional compaction: read + write → access ────────────────────────────
    if compact:
        rule_acc = _compact_rules(rule_acc)

    # ── Build sorted rule list ────────────────────────────────────────────────
    rules = []
    for (agent_label, host, verb), (pids, total) in sorted(rule_acc.items()):
        cn = class_map.get(host, "UnknownAPI")
        rules.append((agent_label, verb, cn, host, pids, total))

    stats = {
        "total_patterns": len(rows),
        "total_observations": sum(r["count"] for r in rows),
        "agent_count": len(named_agents),
        "host_count": len(hosts_seen),
        "rule_count": len(rules),
    }

    return {
        "stats": stats,
        "class_map": class_map,
        "agents": sorted(named_agents),
        "rules": rules,
    }


def _compact_rules(
    rule_acc: dict[tuple, tuple[list, int]]
) -> dict[tuple, tuple[list, int]]:
    """Replace (agent, host, read) + (agent, host, write) → (agent, host, access)."""
    compacted: dict[tuple, tuple[list, int]] = {}
    # Collect keys that can be merged
    read_keys  = {(a, h) for (a, h, v) in rule_acc if v == "read"}
    write_keys = {(a, h) for (a, h, v) in rule_acc if v == "write"}
    mergeable  = read_keys & write_keys  # (agent, host) with both read and write

    for key, val in rule_acc.items():
        agent, host, verb = key
        if (agent, host) in mergeable and verb in ("read", "write"):
            # Merge into an "access" rule
            access_key = (agent, host, "access")
            existing_ids, existing_count = compacted.get(access_key, ([], 0))
            new_ids = existing_ids + val[0]
            compacted[access_key] = (new_ids, existing_count + val[1])
        else:
            compacted[key] = val

    return compacted


# ── ZPL renderer ─────────────────────────────────────────────────────────────

def render_zpl(data: dict) -> str:
    stats    = data["stats"]
    class_map = data["class_map"]
    agents   = data["agents"]
    rules    = data["rules"]

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines: list[str] = []

    # Header
    lines += [
        f"// ZPL Allow Policy — generated from {stats['total_observations']} observations",
        f"// Generated:   {ts}",
        f"// Agents: {stats['agent_count']}  "
        f"Hosts: {stats['host_count']}  "
        f"Rules: {stats['rule_count']}",
        "// Review and edit before activating (set mode: enforce in proxy.yaml)",
        "",
    ]

    # Define blocks — one per unique class name
    unique_classes = sorted(set(class_map.values()))
    if unique_classes:
        lines.append("// ── Resource classes " + "─" * 56)
        for cn in unique_classes:
            lines.append(f"Define {cn} as a service.")
        lines.append("")

    # Declare blocks — one per named agent
    if agents:
        lines.append("// ── Agent declarations " + "─" * 54)
        for agent_id in agents:
            lines.append(f"Declare {agent_id} as a user with name:{agent_id}.")
        lines.append("")

    # Allow rules — grouped by agent
    if rules:
        lines.append("// ── Allow rules " + "─" * 60)
        current_agent = None
        for (agent_label, verb, cn, host, _pids, count) in rules:
            if agent_label != current_agent:
                if current_agent is not None:
                    lines.append("")
                lines.append(f"// {agent_label}  ({count} observations for first rule below)")
                current_agent = agent_label
            verb_pad = verb.ljust(7)
            cn_pad   = cn.ljust(max(len(c) for c in unique_classes) + 1) if unique_classes else cn
            lines.append(f"Allow {agent_label} to {verb_pad} {cn_pad} on {host}.")
        lines.append("")

    lines.append("// Default deny: any request not matched above is blocked in enforce mode.")

    return "\n".join(lines) + "\n"


# ── DB persistence ────────────────────────────────────────────────────────────

def save_rules(db_path: Path, rules: list, zpl_text: str) -> None:
    """Write each Allow rule to the zpl_rules table as a proposed rule."""
    conn = sqlite3.connect(str(db_path))
    now = datetime.now(timezone.utc).isoformat()

    # Mark any previously proposed rules as superseded
    conn.execute("UPDATE zpl_rules SET status='superseded' WHERE status='proposed'")

    for (agent_label, verb, cn, host, pids, count) in rules:
        rule_text = f"Allow {agent_label} to {verb} {cn} on {host}."
        existing = conn.execute(
            "SELECT id FROM zpl_rules WHERE rule_text = ? AND status = 'proposed'",
            (rule_text,),
        ).fetchone()
        if not existing:
            conn.execute(
                """INSERT INTO zpl_rules
                   (generated_at, rule_text, pattern_ids, observation_count, status)
                   VALUES (?, ?, ?, ?, 'proposed')""",
                (now, rule_text, json.dumps(pids), count),
            )

    conn.commit()
    conn.close()


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate a ZPL policy document from observed proxy traffic"
    )
    parser.add_argument("--db", default="data/observations.db",
                        help="Path to observations.db (default: data/observations.db)")
    parser.add_argument("--min-count", type=int, default=1,
                        help="Minimum observation count to include a pattern (default: 1)")
    parser.add_argument("--output", default=None,
                        help="Write ZPL to this file (default: stdout)")
    parser.add_argument("--include-unknown", action="store_true",
                        help="Include unresolved agents as wildcard (*) rules")
    parser.add_argument("--compact", action="store_true",
                        help="Collapse read+write pairs into a single 'access' rule")
    parser.add_argument("--config", default=None,
                        help="Path to proxy.yaml for redact rules")
    parser.add_argument("--save", action="store_true",
                        help="Write rules to the zpl_rules table in the database")
    args = parser.parse_args()

    db_path = Path(args.db)
    if not db_path.exists():
        print(f"Database not found: {db_path}", file=sys.stderr)
        sys.exit(1)

    config_path = Path(args.config) if args.config else None
    if config_path is None:
        candidate = _PROXY_ROOT / "config" / "proxy.yaml"
        if candidate.exists():
            config_path = candidate
    config = load_config(config_path)

    data = generate(
        db_path=db_path,
        min_count=args.min_count,
        include_unknown=args.include_unknown,
        compact=args.compact,
        redact_rules=config.redact,
    )

    if not data["rules"]:
        print(
            f"No patterns with >= {args.min_count} observations yet.",
            file=sys.stderr,
        )
        sys.exit(0)

    zpl = render_zpl(data)

    if args.output:
        Path(args.output).write_text(zpl)
        s = data["stats"]
        print(
            f"Wrote {s['rule_count']} rules "
            f"({s['host_count']} hosts, {s['agent_count']} agents) "
            f"to {args.output}"
        )
    else:
        print(zpl, end="")

    if args.save:
        save_rules(db_path, data["rules"], zpl)
        print(f"Saved {len(data['rules'])} rules to {db_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
