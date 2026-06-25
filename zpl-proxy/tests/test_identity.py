import time
from unittest.mock import MagicMock, patch
import pytest
from zpl_proxy.identity import AgentIdentity, IdentityResolver


def make_resolver(docker_socket="/var/run/docker.sock"):
    return IdentityResolver(
        docker_socket=docker_socket,
        identity_header="X-ZPL-Agent-ID",
        cache_ttl=30,
    )


class TestIdentityResolver:
    def test_docker_hit(self):
        resolver = make_resolver()
        mock_containers = [
            {
                "Names": ["/openclaw"],
                "Labels": {"zpl.agent_id": "openclaw", "zpl.agent_role": "automation-agent"},
                "NetworkSettings": {
                    "Networks": {"lab-net": {"IPAddress": "172.17.0.4"}}
                },
            }
        ]
        mock_resp = MagicMock()
        mock_resp.json.return_value = mock_containers
        mock_resp.raise_for_status = MagicMock()

        with patch.object(resolver._session, "get", return_value=mock_resp):
            identity = resolver.resolve_sync("172.17.0.4", {})

        assert identity.agent_id == "openclaw"
        assert identity.agent_role == "automation-agent"
        assert identity.source == "docker"

    def test_docker_miss_header_fallback(self):
        resolver = make_resolver()
        mock_resp = MagicMock()
        mock_resp.json.return_value = []
        mock_resp.raise_for_status = MagicMock()

        with patch.object(resolver._session, "get", return_value=mock_resp):
            identity = resolver.resolve_sync(
                "10.0.0.1", {"X-ZPL-Agent-ID": "hermes"}
            )

        assert identity.agent_id == "hermes"
        assert identity.source == "header"

    def test_docker_error_header_fallback(self):
        resolver = make_resolver()
        with patch.object(resolver._session, "get", side_effect=Exception("refused")):
            identity = resolver.resolve_sync("10.0.0.2", {"x-zpl-agent-id": "hermes"})

        assert identity.agent_id == "hermes"
        assert identity.source == "header"

    def test_unknown_fallback(self):
        resolver = make_resolver()
        with patch.object(resolver._session, "get", side_effect=Exception("refused")):
            identity = resolver.resolve_sync("10.0.0.3", {})

        assert identity.agent_id == "unknown"
        assert identity.source == "unknown"

    def test_cache_hit_skips_docker(self):
        resolver = make_resolver()
        mock_resp = MagicMock()
        mock_resp.json.return_value = []
        mock_resp.raise_for_status = MagicMock()

        with patch.object(resolver._session, "get", return_value=mock_resp) as mock_get:
            resolver.resolve_sync("10.0.0.4", {"X-ZPL-Agent-ID": "agent1"})
            resolver.resolve_sync("10.0.0.4", {"X-ZPL-Agent-ID": "agent1"})
            # Docker should only be called once (second call hits cache)
            assert mock_get.call_count == 1
