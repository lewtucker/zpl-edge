"""ZPL policy checking — vendored parser/engine from ZPR-Policy-maker-v2.

zpl_parser   — ZPL RFC-15.5 text → {classes, rules, entities} dicts
zpl_engine   — pure evaluator: Never → Allow → default deny, per-rule trace
class_schema — class hierarchy with attribute specs

ROOT_CLASSES seeds the built-in roots the schema requires (the v2 server
loads these from its defaults/; here they are a constant). `servers` is not
a v2 root — it parents to `endpoints` so "Define X as a server" works.
"""
from .class_schema import ClassSchema, ClassSchemaError
from .zpl_engine import CheckRequest, CheckResult, Entity, Rule, ZPLEngine
from .zpl_parser import parse

ROOT_CLASSES: list[dict] = [
    {"class": "users", "parent": None, "builtin": True, "attrs": {}},
    {"class": "endpoints", "parent": None, "builtin": True, "attrs": {}},
    {"class": "services", "parent": None, "builtin": True, "attrs": {}},
    {"class": "servers", "parent": "endpoints", "attrs": {}},
]

__all__ = [
    "ClassSchema", "ClassSchemaError", "CheckRequest", "CheckResult",
    "Entity", "Rule", "ZPLEngine", "parse", "ROOT_CLASSES",
]
