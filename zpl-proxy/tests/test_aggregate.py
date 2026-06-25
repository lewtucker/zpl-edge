"""Bucketed-aggregate egress store (Phase 1b)."""
from zpl_proxy.storage.aggregate import EgressAggregate, normalize_path, query_keys

TG = "/bot8734237758:AAGfWwxaDhpqzGnu-xW1TNc8Cq8cLPzendE/getUpdates"


def test_normalize_collapses_id_segments():
    assert normalize_path("/runs/51e33862-6396-4dae-9b1a-0c2f8d4e7a1b/status") == "/runs/:id/status"
    assert normalize_path("/v1/jobs/123456/log") == "/v1/jobs/:id/log"
    assert normalize_path("/v1/search") == "/v1/search"


def test_normalize_scrubs_embedded_token():
    # the telegram bot token must not survive into the stored / shipped path
    out = normalize_path(TG)
    assert "AAGfWwxaDhpqzGnu" not in out
    assert out.endswith("/getUpdates")
    assert normalize_path(out) == out  # idempotent


def test_query_keys_drops_values():
    assert query_keys("/search?q=secretvalue&page=2") == ["page", "q"]
    assert query_keys("/x") == []


def test_identical_repeats_collapse_to_one_row(tmp_path):
    agg = EgressAggregate(tmp_path / "agg.db")
    for _ in range(2500):
        agg.record(host="api.telegram.org", method="POST", path=TG,
                   ts="2026-06-15T14:30:00+00:00", status=200)
    rows = agg.query()
    assert len(rows) == 1
    assert rows[0]["count"] == 2500
    assert rows[0]["sample_status"] == 200
    assert "AAGfWwxaDhpqzGnu" not in rows[0]["norm_path"]


def test_id_varying_paths_collapse(tmp_path):
    agg = EgressAggregate(tmp_path / "agg.db")
    for i in range(10):
        agg.record(host="robot.local", method="GET",
                   path=f"/runs/{i:08d}-0000-0000-0000-000000000000/status",
                   ts="2026-06-15T14:00:00+00:00")
    rows = agg.query()
    assert len(rows) == 1 and rows[0]["count"] == 10
    assert rows[0]["norm_path"] == "/runs/:id/status"


def test_hourly_buckets_and_time_window(tmp_path):
    agg = EgressAggregate(tmp_path / "agg.db")
    agg.record(host="h", method="GET", path="/a", ts="2026-06-15T13:10:00+00:00")
    agg.record(host="h", method="GET", path="/a", ts="2026-06-15T14:20:00+00:00")
    agg.record(host="h", method="GET", path="/a", ts="2026-06-15T15:30:00+00:00")
    assert len(agg.query()) == 3  # one row per hour
    window = agg.query(since="2026-06-15T14:00:00+00:00", until="2026-06-15T14:59:00+00:00")
    assert len(window) == 1 and window[0]["bucket"] == "2026-06-15T14"


def test_query_keys_merge_across_repeats(tmp_path):
    agg = EgressAggregate(tmp_path / "agg.db")
    agg.record(host="h", method="GET", path="/s?q=1", ts="2026-06-15T14:00:00+00:00")
    agg.record(host="h", method="GET", path="/s?page=2", ts="2026-06-15T14:01:00+00:00")
    rows = agg.query()
    assert len(rows) == 1
    assert rows[0]["query_keys"] == ["page", "q"]
