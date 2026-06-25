"""P0: local-store retention/caps — JSONL rotation + aggregate prune."""
import json

from zpl_proxy.storage.jsonl import JsonlWriter
from zpl_proxy.storage.aggregate import EgressAggregate


def test_jsonl_rotates_on_size(tmp_path):
    p = tmp_path / "requests.jsonl"
    w = JsonlWriter(p, max_bytes=200, backups=2)
    for i in range(50):
        w.write({"i": i, "pad": "x" * 50})
    w.close()
    assert p.exists()                                  # current file present
    assert p.with_suffix(".jsonl.1").exists()          # rotated at least once
    assert p.stat().st_size <= 200 + 100               # current stays bounded


def test_jsonl_no_rotation_when_disabled(tmp_path):
    p = tmp_path / "r.jsonl"
    w = JsonlWriter(p, max_bytes=0)                     # 0 = unbounded
    for i in range(20):
        w.write({"i": i})
    w.close()
    assert not p.with_suffix(".jsonl.1").exists()


def test_aggregate_prune_by_age(tmp_path):
    agg = EgressAggregate(tmp_path / "agg.db")
    agg.record(host="a.com", method="GET", path="/", ts="2026-01-01T10:00:00", agent="x")
    agg.record(host="b.com", method="GET", path="/", ts="2026-06-24T10:00:00", agent="x")
    removed = agg.prune("2026-06-01T00:00:00")          # drop everything before June
    assert removed == 1
    hosts = {r["host"] for r in agg.query()}
    assert hosts == {"b.com"}
