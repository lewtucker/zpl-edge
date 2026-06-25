"""Bucketed-aggregate egress store (Phase 1b — logs-on-proxy).

The watcher is the durable home for its own egress; the hub only pulls slices on
demand. To keep that store from bloating under repetitive polling (an agent's
`api.telegram.org/.../getUpdates` loop produces thousands of identical requests),
we never store one row per request. Instead we keep an HOURLY bucketed aggregate
keyed by ``(host, method, normalized_path, bucket)`` and just bump a counter.

- Identical repeats collapse by definition (same key → one row, count++).
- ID-varying paths (``/runs/<uuid>/status``) collapse via `normalize_path`, which
  also scrubs embedded opaque tokens so secrets (e.g. a telegram bot token) never
  land in the stored — or hub-shipped — path.
- A time-range pull is ``WHERE bucket BETWEEN t0 AND t1``; each row carries its own
  count, so accurate per-window volumes survive the dedup.

`normalize_path` mirrors the hub analyzer's ``_normalize_path`` (same output for the
same path) so proxy aggregates and hub-generated ZPL agree.
"""
from __future__ import annotations

import json
import re
import sqlite3
import threading
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

_UUID = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"

# A whole path segment is "id-shaped" (ephemeral) when it's a uuid, a long hex/opaque
# token, or purely numeric — collapse those so /runs/<uuid>/status dedupes.
_ID_SEGMENT = re.compile(rf"^(?:\d+|{_UUID}|[0-9a-fA-F]{{16,}}|[A-Za-z0-9_.\-]{{24,}})$")

# An opaque token EMBEDDED in a larger segment (e.g. telegram `bot<digits>:<token>`):
# collapse the long run so the secret is scrubbed and tokenized paths still dedupe.
_EMBEDDED_TOKEN = re.compile(rf"(?:{_UUID}|[0-9a-fA-F]{{16,}}|[A-Za-z0-9_\-]{{24,}})")


def normalize_path(path: str) -> str:
    """Collapse id-shaped segments and embedded opaque tokens to ``:id``. Idempotent."""
    path = (path or "/").split("?", 1)[0]
    out = []
    for s in path.split("/"):
        if _ID_SEGMENT.match(s):
            out.append(":id")
        else:
            out.append(_EMBEDDED_TOKEN.sub(":id", s))
    return "/".join(out) or "/"


def query_keys(path_or_url: str) -> list[str]:
    """Distinct query-parameter NAMES (values dropped — never store secrets)."""
    q = urlsplit(path_or_url).query
    if not q:
        return []
    return sorted(parse_qs(q, keep_blank_values=True).keys())


def _bucket(ts: str) -> str:
    """Hourly bucket key from an ISO timestamp: '2026-06-15T14:56:01+00:00' -> '2026-06-15T14'."""
    return (ts or "")[:13]


class EgressAggregate:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            # Multi-agent: `agent` is part of the dedup key so per-agent traffic stays
            # distinct. Older dbs lack the column — drop the derived cache and rebuild it
            # under the new schema (raw requests.jsonl is untouched; only aggregates reset).
            cols = [r[1] for r in self._conn.execute("PRAGMA table_info(egress_agg)").fetchall()]
            if cols and "agent" not in cols:
                self._conn.execute("DROP TABLE egress_agg")
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS egress_agg (
                  agent         TEXT NOT NULL DEFAULT '',
                  host          TEXT NOT NULL,
                  method        TEXT NOT NULL,
                  norm_path     TEXT NOT NULL,
                  bucket        TEXT NOT NULL,
                  count         INTEGER NOT NULL DEFAULT 0,
                  first_seen    TEXT,
                  last_seen     TEXT,
                  sample_status INTEGER,
                  query_keys    TEXT,
                  PRIMARY KEY (agent, host, method, norm_path, bucket)
                );
                CREATE INDEX IF NOT EXISTS idx_egress_agg_bucket ON egress_agg(bucket);
                """
            )
            self._conn.commit()

    def record(self, *, host: str, method: str, path: str, ts: str,
               status: int | None = None, agent: str = "") -> None:
        """Fold one request into the aggregate (UPSERT on the natural key). `agent` is the
        per-agent identity (multi-agent watcher); '' = unattributed (the guard's identity)."""
        agent = agent or ""
        host = (host or "").lower()
        method = (method or "GET").upper()
        norm = normalize_path(path)
        bucket = _bucket(ts)
        new_keys = set(query_keys(path))
        with self._lock:
            row = self._conn.execute(
                """SELECT count, query_keys FROM egress_agg
                   WHERE agent=? AND host=? AND method=? AND norm_path=? AND bucket=?""",
                (agent, host, method, norm, bucket),
            ).fetchone()
            if row:
                merged = sorted(set(json.loads(row["query_keys"] or "[]")) | new_keys)
                self._conn.execute(
                    """UPDATE egress_agg
                       SET count = count + 1, last_seen = ?, sample_status = ?, query_keys = ?
                       WHERE agent=? AND host=? AND method=? AND norm_path=? AND bucket=?""",
                    (ts, status, json.dumps(merged), agent, host, method, norm, bucket),
                )
            else:
                self._conn.execute(
                    """INSERT INTO egress_agg
                       (agent, host, method, norm_path, bucket, count, first_seen, last_seen,
                        sample_status, query_keys)
                       VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?)""",
                    (agent, host, method, norm, bucket, ts, ts, status, json.dumps(sorted(new_keys))),
                )
            self._conn.commit()

    def query(self, since: str | None = None, until: str | None = None) -> list[dict]:
        """Aggregate rows whose hour bucket falls in [since, until] (ISO ts; inclusive).
        Both bounds optional. Newest buckets first, highest count first within a bucket."""
        clauses, params = [], []
        if since:
            clauses.append("bucket >= ?"); params.append(_bucket(since))
        if until:
            clauses.append("bucket <= ?"); params.append(_bucket(until))
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._lock:
            rows = self._conn.execute(
                f"""SELECT agent, host, method, norm_path, bucket, count, first_seen, last_seen,
                           sample_status, query_keys
                    FROM egress_agg {where}
                    ORDER BY bucket DESC, count DESC""",
                params,
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["query_keys"] = json.loads(d["query_keys"] or "[]")
            out.append(d)
        return out

    def prune(self, before_ts: str) -> int:
        """Delete aggregate buckets older than `before_ts` (ISO). Returns rows removed.
        Keeps the local store bounded under a retention window."""
        cutoff = _bucket(before_ts)
        with self._lock:
            cur = self._conn.execute("DELETE FROM egress_agg WHERE bucket < ?", (cutoff,))
            self._conn.commit()
            return cur.rowcount

    def summary(self) -> dict:
        """Lightweight stats for the watcher heartbeat: total events folded, distinct
        endpoint rows, and the oldest/newest bucket retained."""
        with self._lock:
            row = self._conn.execute(
                "SELECT COALESCE(SUM(count),0), COUNT(*), MIN(bucket), MAX(bucket) FROM egress_agg"
            ).fetchone()
        return {"events": row[0], "rows": row[1], "oldest_bucket": row[2], "newest_bucket": row[3]}

    def close(self) -> None:
        self._conn.close()
