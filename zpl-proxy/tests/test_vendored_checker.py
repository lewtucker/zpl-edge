"""The vendored hub ZPL engine, evaluated the way the watcher will call it for
HTTP egress (verb_for_method, service=host, args={path}). Proves the watcher now
matches the hub's model — incl. DELETE→delete (not the old 'operate'), so a true
allow-all really allows everything."""
from zpl_proxy.zpl_checker import compile_rules, check, verb_for_method


def _http(crs, *, user, agent, method, host, path):
    """Mirror replay._replay_decision's HTTP mapping on the hub."""
    return check(crs, user=user, agent_id=agent, tool=path,
                 args={"path": path}, service=host, verb=verb_for_method(method))


# Allow-all in the HUB verb model (read/write/delete + access fallback).
ALLOW_ALL = (
    "allow users to access services.\n"
    "allow users to read services.\n"
    "allow users to write services.\n"
    "allow users to delete services.\n"
)


def test_allow_all_covers_every_method():
    crs = compile_rules(ALLOW_ALL)
    for method in ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "WEIRD"]:
        d = _http(crs, user="LewT", agent="OpenClaw-mini-1", method=method,
                  host="example.com", path="/x")
        assert d.allowed, f"{method} should be allowed by allow-all, got {d.reason}"


SCOPED = (
    'Define "api.anthropic.com" as a server with name:"api.anthropic.com".\n'
    "Define LewT as a user with name:LewT.\n"
    "Define OpenClaw-mini-1 as an endpoint with name:OpenClaw-mini-1.\n"
    'Allow LewT on OpenClaw-mini-1 to write service with path:"/v1" on "api.anthropic.com".\n'
)


def test_scoped_rule_matches_and_default_denies():
    crs = compile_rules(SCOPED)
    # POST to the allowed host + path-prefix → allow
    assert _http(crs, user="LewT", agent="OpenClaw-mini-1", method="POST",
                 host="api.anthropic.com", path="/v1/messages").allowed
    # different host → default-deny
    assert not _http(crs, user="LewT", agent="OpenClaw-mini-1", method="POST",
                     host="evil.com", path="/v1").allowed
    # right host, wrong verb (GET=read, only write allowed) → deny
    assert not _http(crs, user="LewT", agent="OpenClaw-mini-1", method="GET",
                     host="api.anthropic.com", path="/v1").allowed


def test_delete_maps_to_delete_verb():
    # the whole point: DELETE is 'delete' now (hub), so an allow-all incl delete passes
    assert verb_for_method("DELETE") == "delete"
    assert _http(compile_rules(ALLOW_ALL), user="u", agent="a", method="DELETE",
                 host="h.com", path="/x").allowed
