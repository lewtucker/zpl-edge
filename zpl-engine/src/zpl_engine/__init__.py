"""zpl-engine — the shared, framework-free ZPL policy engine.

Single source of truth for ZPL compilation + evaluation. Host packages
(mcp-defender's control/MCP-gateway path and zpl-proxy's HTTP egress watcher)
depend on this and add only their own integration layer. See checker.py for the
live-call adapter and zpl/ for the vendored RFC-15.5 grammar + evaluator.
"""
from __future__ import annotations

from .checker import (
    VERB,
    CompiledRuleSet,
    Decision,
    ZPLCompileError,
    check,
    compile_rules,
    lint_rules,
    service_reachable,
    verb_for_method,
)
from .helpers import _zpl_value, zpl_token

__all__ = [
    "VERB",
    "CompiledRuleSet",
    "Decision",
    "ZPLCompileError",
    "check",
    "compile_rules",
    "lint_rules",
    "service_reachable",
    "verb_for_method",
    "zpl_token",
    "_zpl_value",
]
