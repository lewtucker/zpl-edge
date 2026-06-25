from __future__ import annotations

import json
from dataclasses import dataclass


@dataclass
class McpRequest:
    jsonrpc: str
    method: str
    id: int | str | None
    tool_name: str | None
    tool_args: dict | None


@dataclass
class McpResponse:
    id: int | str | None
    tool_result: list | None
    is_error: bool


def detect_mcp_frame(body: bytes, content_type: str) -> McpRequest | None:
    if not body:
        return None
    if "application/json" not in content_type and "text/plain" not in content_type:
        # MCP over HTTP may use various content types; don't filter too strictly
        if not body.lstrip().startswith(b"{"):
            return None
    try:
        data = json.loads(body)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    if "jsonrpc" not in data or "method" not in data:
        return None

    method = data.get("method", "")
    params = data.get("params") or {}
    tool_name = None
    tool_args = None

    if method == "tools/call":
        tool_name = params.get("name")
        tool_args = params.get("arguments")

    return McpRequest(
        jsonrpc=data.get("jsonrpc", "2.0"),
        method=method,
        id=data.get("id"),
        tool_name=tool_name,
        tool_args=tool_args,
    )


def detect_mcp_response(body: bytes) -> McpResponse | None:
    if not body:
        return None
    try:
        data = json.loads(body)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    if "jsonrpc" not in data and "result" not in data and "error" not in data:
        return None

    is_error = "error" in data
    tool_result = None

    if not is_error:
        result = data.get("result") or {}
        # MCP tools/call response: result.content is a list of content blocks
        tool_result = result.get("content") if isinstance(result, dict) else None

    return McpResponse(
        id=data.get("id"),
        tool_result=tool_result,
        is_error=is_error,
    )
