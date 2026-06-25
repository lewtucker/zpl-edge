import json
import sqlite3
import tempfile
from pathlib import Path

import pytest

# The analyze module lives under scripts/, not the package — import directly.
import importlib.util, sys

_SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"
spec = importlib.util.spec_from_file_location("analyze", _SCRIPTS_DIR / "analyze.py")
analyze = importlib.util.module_from_spec(spec)
spec.loader.exec_module(analyze)

_sld          = analyze._sld
_class_name   = analyze._class_name
host_to_class = analyze.host_to_class
generalize_path = analyze.generalize_path
generate      = analyze.generate
render_zpl    = analyze.render_zpl
_compact_rules = analyze._compact_rules


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _make_db(rows: list[dict]) -> Path:
    """Write pattern rows to a temp SQLite DB and return its path."""
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    path = Path(tmp.name)

    conn = sqlite3.connect(str(path))
    conn.executescript("""
        CREATE TABLE patterns (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id    TEXT,
            dest_host   TEXT,
            method      TEXT,
            path        TEXT,
            tool_name   TEXT,
            first_seen  TEXT NOT NULL DEFAULT '2025-01-01T00:00:00Z',
            last_seen   TEXT NOT NULL DEFAULT '2025-01-01T00:00:00Z',
            count       INTEGER DEFAULT 1,
            zpl_rule    TEXT
        );
        CREATE TABLE zpl_rules (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            generated_at      TEXT NOT NULL,
            rule_text         TEXT NOT NULL,
            pattern_ids       TEXT NOT NULL,
            observation_count INTEGER,
            status            TEXT DEFAULT 'proposed'
        );
    """)
    for row in rows:
        conn.execute(
            """INSERT INTO patterns (agent_id, dest_host, method, path, tool_name, count)
               VALUES (:agent_id, :dest_host, :method, :path, :tool_name, :count)""",
            row,
        )
    conn.commit()
    conn.close()
    return path


def _default_row(**kwargs) -> dict:
    base = {
        "agent_id": "openclaw",
        "dest_host": "api.anthropic.com",
        "method": "POST",
        "path": "/v1/messages",
        "tool_name": None,
        "count": 3,
    }
    base.update(kwargs)
    return base


# ── _sld ──────────────────────────────────────────────────────────────────────

class TestSld:
    def test_simple_domain(self):
        assert _sld("anthropic.com") == "anthropic"

    def test_api_subdomain(self):
        assert _sld("api.anthropic.com") == "anthropic"

    def test_multiple_subdomains(self):
        assert _sld("cdn.static.openai.com") == "openai"

    def test_io_tld(self):
        assert _sld("huggingface.io") == "huggingface"

    def test_ai_tld(self):
        assert _sld("cohere.ai") == "cohere"

    def test_hyphenated_sld(self):
        assert _sld("applied-invention.com") == "applied-invention"

    def test_ip_address(self):
        assert _sld("192.168.1.1") == "192.168.1.1"

    def test_localhost(self):
        # No dots → no TLD stripping
        assert _sld("localhost") == "localhost"

    def test_co_uk(self):
        # naively strips .uk then .co, leaving the SLD
        assert _sld("api.example.co.uk") == "example"


# ── _class_name ───────────────────────────────────────────────────────────────

class TestClassName:
    def test_simple(self):
        assert _class_name("anthropic") == "AnthropicAPI"

    def test_hyphenated(self):
        assert _class_name("applied-invention") == "AppliedInventionAPI"

    def test_underscored(self):
        assert _class_name("open_ai") == "OpenAiAPI"

    def test_already_titlecase(self):
        assert _class_name("OpenAI") == "OpenaiAPI"

    def test_empty(self):
        assert _class_name("") == "UnknownAPI"


class TestHostToClass:
    def test_api_subdomain(self):
        assert host_to_class("api.anthropic.com") == "AnthropicAPI"

    def test_ip_passthrough(self):
        # IP → class name includes the dots-replaced form
        result = host_to_class("192.168.1.1")
        assert result.endswith("API")

    def test_hyphenated_sld(self):
        assert host_to_class("api.applied-invention.com") == "AppliedInventionAPI"


# ── generalize_path ───────────────────────────────────────────────────────────

class TestGeneralizePath:
    def test_none(self):
        assert generalize_path(None) is None

    def test_empty(self):
        assert generalize_path("") == ""

    def test_no_change(self):
        assert generalize_path("/v1/messages") == "/v1/messages"

    def test_uuid(self):
        p = generalize_path("/runs/123e4567-e89b-12d3-a456-426614174000/status")
        assert "*" in p
        assert "123e4567" not in p

    def test_numeric_segment(self):
        p = generalize_path("/items/42/detail")
        assert p == "/items/*/detail"

    def test_short_number_preserved(self):
        # Single digit should NOT be replaced (only 2+ digit numeric segments)
        p = generalize_path("/v1/items")
        assert p == "/v1/items"

    def test_hex_segment(self):
        p = generalize_path("/blobs/abcdef0123456789abcdef/download")
        assert "*" in p
        assert "abcdef0123456789" not in p

    def test_multiple_variables(self):
        p = generalize_path("/runs/99/steps/abcdef0123456789/result")
        assert p.count("*") == 2


# ── generate ──────────────────────────────────────────────────────────────────

class TestGenerate:
    def test_basic(self):
        db = _make_db([_default_row()])
        data = generate(db, min_count=1, include_unknown=False, compact=False, redact_rules=[])
        assert data["stats"]["rule_count"] == 1
        assert data["stats"]["agent_count"] == 1
        assert data["stats"]["host_count"] == 1

    def test_min_count_filters(self):
        db = _make_db([_default_row(count=1)])
        data = generate(db, min_count=3, include_unknown=False, compact=False, redact_rules=[])
        assert data["stats"]["rule_count"] == 0

    def test_unknown_excluded_by_default(self):
        db = _make_db([_default_row(agent_id=None)])
        data = generate(db, min_count=1, include_unknown=False, compact=False, redact_rules=[])
        assert data["stats"]["rule_count"] == 0

    def test_unknown_included(self):
        db = _make_db([_default_row(agent_id=None)])
        data = generate(db, min_count=1, include_unknown=True, compact=False, redact_rules=[])
        assert data["stats"]["rule_count"] == 1
        agent_label, verb, cn, host, pids, count = data["rules"][0]
        assert agent_label == "*"

    def test_class_map_built(self):
        db = _make_db([_default_row(dest_host="api.anthropic.com")])
        data = generate(db, min_count=1, include_unknown=False, compact=False, redact_rules=[])
        assert data["class_map"]["api.anthropic.com"] == "AnthropicAPI"

    def test_subdomains_same_class(self):
        db = _make_db([
            _default_row(dest_host="api.anthropic.com"),
            _default_row(dest_host="cdn.anthropic.com", method="GET"),
        ])
        data = generate(db, min_count=1, include_unknown=False, compact=False, redact_rules=[])
        assert data["class_map"]["api.anthropic.com"] == data["class_map"]["cdn.anthropic.com"]

    def test_verb_get_read(self):
        db = _make_db([_default_row(method="GET", tool_name=None)])
        data = generate(db, min_count=1, include_unknown=False, compact=False, redact_rules=[])
        _, verb, *_ = data["rules"][0]
        assert verb == "read"

    def test_verb_post_write(self):
        db = _make_db([_default_row(method="POST", tool_name=None)])
        data = generate(db, min_count=1, include_unknown=False, compact=False, redact_rules=[])
        _, verb, *_ = data["rules"][0]
        assert verb == "write"

    def test_verb_delete_operate(self):
        db = _make_db([_default_row(method="DELETE", tool_name=None)])
        data = generate(db, min_count=1, include_unknown=False, compact=False, redact_rules=[])
        _, verb, *_ = data["rules"][0]
        assert verb == "operate"

    def test_verb_tool_use(self):
        db = _make_db([_default_row(tool_name="get_run_status")])
        data = generate(db, min_count=1, include_unknown=False, compact=False, redact_rules=[])
        _, verb, *_ = data["rules"][0]
        assert verb == "use"

    def test_deduplication(self):
        # Two rows with same (agent, host, verb) should collapse to one rule
        db = _make_db([
            _default_row(method="GET", path="/v1/a"),
            _default_row(method="GET", path="/v1/b"),
        ])
        data = generate(db, min_count=1, include_unknown=False, compact=False, redact_rules=[])
        assert data["stats"]["rule_count"] == 1

    def test_multiple_agents(self):
        db = _make_db([
            _default_row(agent_id="openclaw"),
            _default_row(agent_id="hermes"),
        ])
        data = generate(db, min_count=1, include_unknown=False, compact=False, redact_rules=[])
        assert data["stats"]["agent_count"] == 2
        assert data["stats"]["rule_count"] == 2

    def test_observation_count_sum(self):
        db = _make_db([
            _default_row(method="GET", path="/v1/a", count=5),
            _default_row(method="GET", path="/v1/b", count=3),
        ])
        data = generate(db, min_count=1, include_unknown=False, compact=False, redact_rules=[])
        _, _verb, _cn, _host, _pids, total = data["rules"][0]
        assert total == 8


# ── _compact_rules ────────────────────────────────────────────────────────────

class TestCompactRules:
    def _make_acc(self, triples):
        return {(a, h, v): ([i], c) for i, (a, h, v, c) in enumerate(triples)}

    def test_read_write_merged(self):
        acc = self._make_acc([
            ("oc", "api.x.com", "read",  2),
            ("oc", "api.x.com", "write", 3),
        ])
        result = _compact_rules(acc)
        assert ("oc", "api.x.com", "access") in result
        assert ("oc", "api.x.com", "read")   not in result
        assert ("oc", "api.x.com", "write")  not in result

    def test_count_summed(self):
        acc = self._make_acc([
            ("oc", "api.x.com", "read",  2),
            ("oc", "api.x.com", "write", 3),
        ])
        result = _compact_rules(acc)
        _, total = result[("oc", "api.x.com", "access")]
        assert total == 5

    def test_read_only_not_merged(self):
        acc = self._make_acc([("oc", "api.x.com", "read", 2)])
        result = _compact_rules(acc)
        assert ("oc", "api.x.com", "read") in result
        assert ("oc", "api.x.com", "access") not in result

    def test_operate_preserved(self):
        acc = self._make_acc([
            ("oc", "api.x.com", "read",    2),
            ("oc", "api.x.com", "write",   1),
            ("oc", "api.x.com", "operate", 1),
        ])
        result = _compact_rules(acc)
        assert ("oc", "api.x.com", "access")  in result
        assert ("oc", "api.x.com", "operate") in result

    def test_different_agents_not_merged(self):
        acc = self._make_acc([
            ("oc",     "api.x.com", "read",  2),
            ("hermes", "api.x.com", "write", 1),
        ])
        result = _compact_rules(acc)
        assert ("oc",     "api.x.com", "read")  in result
        assert ("hermes", "api.x.com", "write") in result
        assert ("oc",     "api.x.com", "access") not in result


# ── render_zpl ────────────────────────────────────────────────────────────────

class TestRenderZpl:
    def _data(self, extra_rows=None):
        rows = [_default_row()]
        if extra_rows:
            rows += extra_rows
        db = _make_db(rows)
        return generate(db, min_count=1, include_unknown=False, compact=False, redact_rules=[])

    def test_has_header(self):
        zpl = render_zpl(self._data())
        assert "ZPL Allow Policy" in zpl

    def test_has_define(self):
        zpl = render_zpl(self._data())
        assert "Define AnthropicAPI as a service." in zpl

    def test_has_declare(self):
        zpl = render_zpl(self._data())
        assert "Declare openclaw as a user" in zpl

    def test_has_allow(self):
        zpl = render_zpl(self._data())
        assert "Allow openclaw to" in zpl
        assert "api.anthropic.com" in zpl

    def test_allow_verb_write(self):
        zpl = render_zpl(self._data())
        assert "write" in zpl

    def test_default_deny_comment(self):
        zpl = render_zpl(self._data())
        assert "Default deny" in zpl

    def test_ends_with_newline(self):
        zpl = render_zpl(self._data())
        assert zpl.endswith("\n")

    def test_multiple_classes_sorted(self):
        db = _make_db([
            _default_row(dest_host="api.anthropic.com"),
            _default_row(dest_host="api.openai.com", agent_id="hermes"),
        ])
        data = generate(db, min_count=1, include_unknown=False, compact=False, redact_rules=[])
        zpl = render_zpl(data)
        idx_a = zpl.index("AnthropicAPI")
        idx_o = zpl.index("OpenaiAPI")
        assert idx_a < idx_o  # sorted alphabetically

    def test_compact_produces_access_verb(self):
        db = _make_db([
            _default_row(method="GET"),
            _default_row(method="POST"),
        ])
        data = generate(db, min_count=1, include_unknown=False, compact=True, redact_rules=[])
        zpl = render_zpl(data)
        assert "access" in zpl
        assert "read" not in zpl.split("//")[1]  # not in rule section
