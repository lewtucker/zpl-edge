"""Minimal name/value tokenization shared by rule generation and live checking.

Both the rule writer (analyzer) and the checker must pass names/values through
these, or rules written from logs never match the calls they came from. Kept
here (not in any host package) so the engine has no framework dependency.
"""
from __future__ import annotations

import re


def zpl_token(value: str) -> str:
    """Sanitize any name (agent id, tool, service) into a single ZPL token.

    Generated rules and live-call checking must both pass names through this,
    or rules written from logs will never match the calls they came from.
    """
    value = (value or "").strip()
    if not value:
        return "unknown"
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", value)


def _zpl_value(v) -> str:
    """Encode a Python arg value as its ZPL string representation.

    Booleans → "true"/"false".  Dicts/lists → "" (wildcard: present, any value).
    Everything else → str(v).
    """
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (dict, list)):
        return ""
    if v is None:
        return ""
    return str(v)
