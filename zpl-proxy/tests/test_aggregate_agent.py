"""Multi-agent watcher: the egress aggregate keeps per-agent buckets distinct."""
from zpl_proxy.storage.aggregate import EgressAggregate


def test_aggregate_tracks_agent(tmp_path):
    agg = EgressAggregate(tmp_path / "agg.db")
    common = dict(host="api.x.com", method="GET", path="/v1", ts="2026-06-24T10:00:00", status=200)
    agg.record(**common, agent="Hermes")
    agg.record(**common, agent="")          # unattributed (→ guard agent at ingest)
    agg.record(**common, agent="Hermes")     # folds into the Hermes bucket

    rows = agg.query()
    assert sorted(r["agent"] for r in rows) == ["", "Hermes"]   # distinct per agent
    hermes = [r for r in rows if r["agent"] == "Hermes"][0]
    assert hermes["count"] == 2 and hermes["host"] == "api.x.com"


def test_aggregate_carries_subject_per_agent(tmp_path):
    agg = EgressAggregate(tmp_path / "agg.db")
    common = dict(host="api.x.com", method="GET", path="/v1", ts="2026-06-24T10:00:00", status=200)
    agg.record(**common, agent="hermes", subject="kyle")
    agg.record(**common, agent="Openclaw", subject="Kyle-OC")

    rows = {r["agent"]: r for r in agg.query()}
    assert rows["hermes"]["subject"] == "kyle"
    assert rows["Openclaw"]["subject"] == "Kyle-OC"
