"""Config loading — ignore_hosts pass-through list."""
from zpl_proxy.config import load_config


def test_ignore_hosts_parsed(tmp_path):
    cfg = tmp_path / "proxy.yaml"
    cfg.write_text("ignore_hosts:\n  - api.telegram.org\n")
    assert load_config(cfg).ignore_hosts == ["api.telegram.org"]


def test_ignore_hosts_local_appends(tmp_path):
    (tmp_path / "proxy.yaml").write_text("ignore_hosts: [a.com]\n")
    (tmp_path / "proxy.local.yaml").write_text("ignore_hosts: [b.com]\n")
    assert load_config(tmp_path / "proxy.yaml").ignore_hosts == ["a.com", "b.com"]


def test_ignore_hosts_default_empty(tmp_path):
    (tmp_path / "proxy.yaml").write_text("listen_port: 8080\n")
    assert load_config(tmp_path / "proxy.yaml").ignore_hosts == []
