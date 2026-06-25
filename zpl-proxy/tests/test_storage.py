import json
import sqlite3
import tempfile
from pathlib import Path
from datetime import datetime, timezone

import pytest
from zpl_proxy.storage.db import Database
from zpl_proxy.storage.jsonl import JsonlWriter


def make_record(**overrides) -> dict:
    base = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "agent_id": "openclaw",
        "agent_role": "automation-agent",
        "peer_ip": "172.17.0.4",
        "identity_source": "docker",
        "request_type": "mcp",
        "dest_host": "opentrons-mcp-server",
        "dest_port": 80,
        "method": "POST",
        "path": "/",
        "request_headers": json.dumps({"content-type": "application/json"}),
        "request_body": '{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":"get_run_status"}}',
        "mcp_method": "tools/call",
        "tool_name": "get_run_status",
        "tool_args": json.dumps({"run_id": "run-001"}),
        "response_code": 200,
        "response_time_ms": 42,
        "response_headers": json.dumps({"content-type": "application/json"}),
        "response_body": '{"jsonrpc":"2.0","id":1,"result":{"content":[]}}',
        "tool_result": json.dumps([]),
    }
    base.update(overrides)
    return base


class TestDatabase:
    def test_insert_creates_request_row(self, tmp_path):
        db = Database(tmp_path / "test.db")
        record = make_record()
        row_id = db.insert(record)
        assert row_id is not None and row_id > 0

        conn = sqlite3.connect(str(tmp_path / "test.db"))
        row = conn.execute("SELECT agent_id, tool_name FROM requests WHERE id = ?", (row_id,)).fetchone()
        assert row[0] == "openclaw"
        assert row[1] == "get_run_status"
        conn.close()
        db.close()

    def test_pattern_created_on_first_insert(self, tmp_path):
        db = Database(tmp_path / "test.db")
        db.insert(make_record())

        conn = sqlite3.connect(str(tmp_path / "test.db"))
        row = conn.execute("SELECT count FROM patterns WHERE agent_id = 'openclaw' AND tool_name = 'get_run_status'").fetchone()
        assert row is not None
        assert row[0] == 1
        conn.close()
        db.close()

    def test_pattern_count_increments(self, tmp_path):
        db = Database(tmp_path / "test.db")
        db.insert(make_record())
        db.insert(make_record())
        db.insert(make_record())

        conn = sqlite3.connect(str(tmp_path / "test.db"))
        row = conn.execute("SELECT count FROM patterns WHERE agent_id = 'openclaw' AND tool_name = 'get_run_status'").fetchone()
        assert row[0] == 3
        conn.close()
        db.close()

    def test_different_tools_create_different_patterns(self, tmp_path):
        db = Database(tmp_path / "test.db")
        db.insert(make_record(tool_name="get_run_status"))
        db.insert(make_record(tool_name="run_protocol"))

        conn = sqlite3.connect(str(tmp_path / "test.db"))
        rows = conn.execute("SELECT tool_name FROM patterns WHERE agent_id = 'openclaw'").fetchall()
        tools = {r[0] for r in rows}
        assert tools == {"get_run_status", "run_protocol"}
        conn.close()
        db.close()


class TestJsonlWriter:
    def test_write_creates_valid_jsonl(self, tmp_path):
        path = tmp_path / "out.jsonl"
        writer = JsonlWriter(path)
        record = make_record()
        writer.write(record)
        writer.write(make_record(tool_name="run_protocol"))
        writer.close()

        lines = path.read_text().strip().splitlines()
        assert len(lines) == 2
        for line in lines:
            parsed = json.loads(line)
            assert "ts" in parsed
            assert "agent_id" in parsed

    def test_append_mode(self, tmp_path):
        path = tmp_path / "out.jsonl"
        JsonlWriter(path).write(make_record())
        JsonlWriter(path).write(make_record())
        lines = path.read_text().strip().splitlines()
        assert len(lines) == 2
