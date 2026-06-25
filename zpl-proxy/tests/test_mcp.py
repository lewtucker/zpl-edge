import json
import pytest
from zpl_proxy.mcp import detect_mcp_frame, detect_mcp_response, McpRequest, McpResponse


def _body(data: dict) -> bytes:
    return json.dumps(data).encode()


CT = "application/json"


class TestDetectMcpFrame:
    def test_tools_call(self):
        body = _body({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 1,
            "params": {"name": "run_protocol", "arguments": {"run_id": "r1"}},
        })
        result = detect_mcp_frame(body, CT)
        assert isinstance(result, McpRequest)
        assert result.method == "tools/call"
        assert result.tool_name == "run_protocol"
        assert result.tool_args == {"run_id": "r1"}

    def test_tools_list(self):
        body = _body({"jsonrpc": "2.0", "method": "tools/list", "id": 2, "params": {}})
        result = detect_mcp_frame(body, CT)
        assert isinstance(result, McpRequest)
        assert result.method == "tools/list"
        assert result.tool_name is None

    def test_initialize(self):
        body = _body({"jsonrpc": "2.0", "method": "initialize", "id": 0, "params": {}})
        result = detect_mcp_frame(body, CT)
        assert isinstance(result, McpRequest)
        assert result.method == "initialize"

    def test_non_json_body(self):
        assert detect_mcp_frame(b"not json", CT) is None

    def test_empty_body(self):
        assert detect_mcp_frame(b"", CT) is None

    def test_json_but_not_jsonrpc(self):
        body = _body({"foo": "bar"})
        assert detect_mcp_frame(body, CT) is None

    def test_malformed_json(self):
        assert detect_mcp_frame(b"{bad json}", CT) is None

    def test_json_array(self):
        assert detect_mcp_frame(b"[1,2,3]", CT) is None


class TestDetectMcpResponse:
    def test_tools_call_response(self):
        body = _body({
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "content": [{"type": "text", "text": "ok"}]
            },
        })
        result = detect_mcp_response(body)
        assert isinstance(result, McpResponse)
        assert result.is_error is False
        assert result.tool_result == [{"type": "text", "text": "ok"}]

    def test_error_response(self):
        body = _body({
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"code": -32601, "message": "Method not found"},
        })
        result = detect_mcp_response(body)
        assert isinstance(result, McpResponse)
        assert result.is_error is True
        assert result.tool_result is None

    def test_empty(self):
        assert detect_mcp_response(b"") is None

    def test_non_jsonrpc(self):
        assert detect_mcp_response(b'{"foo": "bar"}') is None
