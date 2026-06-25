from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path


class Database:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        self._init_schema()

    def _init_schema(self) -> None:
        schema = (Path(__file__).parent / "schema.sql").read_text()
        with self._lock:
            self._conn.executescript(schema)
            self._conn.commit()

    def insert(self, record: dict) -> int:
        pattern_id = self._upsert_pattern(record)
        record = {**record, "pattern_id": pattern_id}

        cols = [
            "ts", "agent_id", "agent_role", "peer_ip", "identity_source",
            "request_type", "dest_host", "dest_port", "method", "path",
            "request_headers", "request_body",
            "mcp_method", "tool_name", "tool_args",
            "response_code", "response_time_ms", "response_headers", "response_body",
            "tool_result", "pattern_id",
            "policy_verdict", "policy_rule_id",
        ]
        placeholders = ", ".join("?" for _ in cols)
        col_names = ", ".join(cols)
        values = [record.get(c) for c in cols]

        with self._lock:
            cur = self._conn.execute(
                f"INSERT INTO requests ({col_names}) VALUES ({placeholders})",
                values,
            )
            self._conn.commit()
            return cur.lastrowid

    def _upsert_pattern(self, record: dict) -> int | None:
        agent_id = record.get("agent_id")
        dest_host = record.get("dest_host")
        method = record.get("method")
        path = record.get("path")
        tool_name = record.get("tool_name")
        ts = record.get("ts")

        with self._lock:
            row = self._conn.execute(
                """SELECT id FROM patterns
                   WHERE agent_id IS ? AND dest_host IS ? AND method IS ?
                     AND path IS ? AND tool_name IS ?""",
                (agent_id, dest_host, method, path, tool_name),
            ).fetchone()

            if row:
                self._conn.execute(
                    "UPDATE patterns SET count = count + 1, last_seen = ? WHERE id = ?",
                    (ts, row["id"]),
                )
                self._conn.commit()
                return row["id"]
            else:
                cur = self._conn.execute(
                    """INSERT INTO patterns
                       (agent_id, dest_host, method, path, tool_name, first_seen, last_seen)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (agent_id, dest_host, method, path, tool_name, ts, ts),
                )
                self._conn.commit()
                return cur.lastrowid

    def close(self) -> None:
        self._conn.close()
