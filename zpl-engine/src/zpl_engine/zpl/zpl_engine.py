# Vendored from ZPR-Policy-maker-v2 (commit 3e818aa, 2026-05-15)
# src/server/ — evolves independently here; do not sync blindly.
"""ZPL RFC-15.5 policy engine.

Pure evaluator: no I/O, no database, no network. Given a :class:`ClassSchema`,
a list of :class:`Rule` objects, and a :class:`CheckRequest`, returns a
:class:`CheckResult` with the verdict plus a per-rule trace for debugging.

Rule YAML shape::

    rules:
      - id: <uuid>
        name: Sales access customer DBs
        description: ...
        result: allow               # allow | never
        priority: 100               # higher = evaluated first
        verb: access                # null = any
        subject:                    # null = unconstrained
          class: employee
          attrs:
            department: sales
        accessor_endpoint:          # optional "on <endpoint>" before "to"
          class: laptop
          attrs: { managed: "*" }
        object:
          class: database           # or: name: Timesheet-database
          attrs: { data: customer }
        server_endpoint: null
        signal:                     # optional
          message: accessing
          to: Access-logger
        protected: false

Evaluation order::

    never rules (priority desc) → first match → deny
    allow rules (priority desc) → first match → allow
    no match                                  → deny (default)
"""
from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Literal

import yaml

from .class_schema import ClassSchema

# ── Data classes ────────────────────────────────────────────────────────────


@dataclass
class Spec:
    """One slot in a rule: class and/or named entity, plus attribute filters.

    A spec is satisfied when all of:
    - the entity's class equals ``class_name`` or descends from it (if set)
    - the entity's name equals ``name`` (if set)
    - every (attr → value) pair in ``attrs`` matches the entity's attrs
    """

    class_name: str | None = None
    name: str | None = None
    attrs: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict | None) -> "Spec | None":
        if data is None:
            return None
        return cls(
            class_name=data.get("class"),
            name=data.get("name"),
            attrs=dict(data.get("attrs") or {}),
        )

    def to_dict(self) -> dict:
        out: dict[str, Any] = {}
        if self.class_name:
            out["class"] = self.class_name
        if self.name:
            out["name"] = self.name
        if self.attrs:
            out["attrs"] = dict(self.attrs)
        return out


@dataclass
class Rule:
    id: str
    name: str
    result: Literal["allow", "never"]
    priority: int = 100
    verb: str | None = None
    subject: Spec | None = None
    accessor_endpoint: Spec | None = None
    object: Spec | None = None
    server_endpoint: Spec | None = None
    signal: dict | None = None
    description: str = ""
    protected: bool = False
    # Phase A conditions: a CEL expression evaluated after the spec match. Only
    # narrows (turns a matched Allow into a deny); Allow rules only. See
    # docs/architecture/zpl-conditions.md.
    condition: str | None = None

    @classmethod
    def from_dict(cls, data: dict) -> "Rule":
        result = data.get("result")
        if result not in ("allow", "never"):
            raise ValueError(
                f"rule {data.get('id')!r} has invalid result: {result!r}"
            )
        return cls(
            id=data.get("id") or uuid.uuid4().hex,
            name=data.get("name") or "",
            result=result,
            priority=int(data.get("priority", 100)),
            verb=data.get("verb") or None,
            subject=Spec.from_dict(data.get("subject")),
            accessor_endpoint=Spec.from_dict(data.get("accessor_endpoint")),
            object=Spec.from_dict(data.get("object")),
            server_endpoint=Spec.from_dict(data.get("server_endpoint")),
            signal=data.get("signal") or None,
            description=data.get("description") or "",
            protected=bool(data.get("protected", False)),
            condition=data.get("condition") or None,
        )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "result": self.result,
            "priority": self.priority,
            "verb": self.verb,
            "subject": self.subject.to_dict() if self.subject else None,
            "accessor_endpoint": (
                self.accessor_endpoint.to_dict() if self.accessor_endpoint else None
            ),
            "object": self.object.to_dict() if self.object else None,
            "server_endpoint": (
                self.server_endpoint.to_dict() if self.server_endpoint else None
            ),
            "signal": dict(self.signal) if self.signal else None,
            "protected": self.protected,
            **({"condition": self.condition} if self.condition else {}),
        }


@dataclass
class Entity:
    """An instance: a class plus optional identity (name) plus concrete attrs."""

    class_name: str
    name: str | None = None
    attrs: dict[str, Any] = field(default_factory=dict)


@dataclass
class CheckRequest:
    subject: Entity
    object: Entity
    verb: str
    accessor_endpoint: Entity | None = None
    server_endpoint: Entity | None = None
    # Context for rule conditions (Phase A): {"now": {hour, minute, ...}, "args": {...}}.
    context: dict = field(default_factory=dict)


@dataclass
class SlotMatch:
    matched: bool
    reason: str = ""


@dataclass
class RuleTrace:
    rule_id: str
    rule_name: str
    result: str
    priority: int
    matched: bool
    slot_matches: dict[str, SlotMatch]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["slot_matches"] = {k: asdict(v) for k, v in self.slot_matches.items()}
        return d


@dataclass
class CheckResult:
    verdict: Literal["allow", "deny"]
    rule_id: str | None = None
    rule_name: str | None = None
    signal: dict | None = None
    trace: list[RuleTrace] = field(default_factory=list)


# ── Engine ──────────────────────────────────────────────────────────────────


class ZPLEngine:
    """Pure policy evaluator over a fixed rule set and class schema."""

    def __init__(self, rules: list[Rule], schema: ClassSchema):
        self.rules = list(rules)
        self.schema = schema
        # Compile each rule's `when:` CEL once, up front, so a bad expression is
        # an error at rule-load (not at first call). Conditions are Allow-only —
        # a Never is absolute and nothing may narrow it.
        self._conditions: dict[str, Any] = {}
        for r in self.rules:
            if not r.condition:
                continue
            if r.result != "allow":
                raise ValueError(
                    f"rule '{r.name}': when: conditions are only allowed on Allow "
                    f"rules (a Never rule is absolute and cannot be narrowed)."
                )
            self._conditions[r.id] = _compile_cel(r.condition, r.name)

    # ── evaluation ──────────────────────────────────────────────────────

    def evaluate(self, request: CheckRequest) -> CheckResult:
        nevers = sorted(
            (r for r in self.rules if r.result == "never"),
            key=lambda r: -r.priority,
        )
        allows = sorted(
            (r for r in self.rules if r.result == "allow"),
            key=lambda r: -r.priority,
        )

        trace: list[RuleTrace] = []

        for rule in nevers:
            rt = self._match_rule(rule, request)
            trace.append(rt)
            if rt.matched:
                return CheckResult(
                    verdict="deny",
                    rule_id=rule.id,
                    rule_name=rule.name,
                    signal=dict(rule.signal) if rule.signal else None,
                    trace=trace,
                )

        for rule in allows:
            rt = self._match_rule(rule, request)
            trace.append(rt)
            if rt.matched:
                return CheckResult(
                    verdict="allow",
                    rule_id=rule.id,
                    rule_name=rule.name,
                    signal=dict(rule.signal) if rule.signal else None,
                    trace=trace,
                )

        return CheckResult(verdict="deny", trace=trace)

    # ── matchers ────────────────────────────────────────────────────────

    def _match_rule(self, rule: Rule, req: CheckRequest) -> RuleTrace:
        slot_matches = {
            "subject": self._match_spec("subject", rule.subject, req.subject),
            "accessor_endpoint": self._match_spec(
                "accessor_endpoint", rule.accessor_endpoint, req.accessor_endpoint
            ),
            "verb": self._match_verb(rule.verb, req.verb),
            "object": self._match_spec("object", rule.object, req.object),
            "server_endpoint": self._match_spec(
                "server_endpoint", rule.server_endpoint, req.server_endpoint
            ),
        }
        matched = all(sm.matched for sm in slot_matches.values())
        # Conditions only narrow: once every spec slot matches an Allow rule,
        # its `when:` must also hold or the rule doesn't fire (fail-closed).
        if matched and rule.id in self._conditions:
            ok, detail = _eval_condition(self._conditions[rule.id], req.context)
            slot_matches["condition"] = SlotMatch(
                ok, f"when:{rule.condition!r} → " + ("pass" if ok else detail)
            )
            matched = ok
        return RuleTrace(
            rule_id=rule.id,
            rule_name=rule.name,
            result=rule.result,
            priority=rule.priority,
            matched=matched,
            slot_matches=slot_matches,
        )

    def _match_spec(
        self, slot: str, spec: Spec | None, entity: Entity | None
    ) -> SlotMatch:
        if spec is None:
            return SlotMatch(True, f"{slot}: unconstrained")
        if entity is None:
            return SlotMatch(False, f"{slot}: request has no entity, rule requires one")

        if spec.name is not None:
            if entity.name != spec.name:
                return SlotMatch(
                    False, f"{slot}: name {entity.name!r} ≠ {spec.name!r}"
                )

        if spec.class_name is not None:
            entity_known = self.schema.has(entity.class_name)
            spec_known   = self.schema.has(spec.class_name)
            if entity_known and spec_known:
                if not self.schema.is_subclass(entity.class_name, spec.class_name):
                    return SlotMatch(
                        False,
                        f"{slot}: class {entity.class_name!r} is not a {spec.class_name!r}",
                    )
            elif entity_known != spec_known:
                which = "entity" if not entity_known else "rule"
                unknown = entity.class_name if not entity_known else spec.class_name
                return SlotMatch(False, f"{slot}: unknown {which} class {unknown!r}")
            else:
                # neither in schema — fall back to exact name equality
                if entity.class_name != spec.class_name:
                    return SlotMatch(
                        False,
                        f"{slot}: class {entity.class_name!r} ≠ {spec.class_name!r}",
                    )

        for attr_name, spec_value in spec.attrs.items():
            entity_value = entity.attrs.get(attr_name)
            # The object's `path` attribute matches by segment-prefix (HTTP egress:
            # a rule path covers itself and everything under it). All other attrs —
            # and every other slot — keep exact set-overlap matching (MCP unchanged).
            if slot == "object" and attr_name == "path":
                ok = _path_attr_matches(spec_value, entity_value)
            else:
                ok = _attr_matches(spec_value, entity_value)
            if not ok:
                return SlotMatch(
                    False,
                    f"{slot}: attr {attr_name}={entity_value!r} "
                    f"does not match {spec_value!r}",
                )

        return SlotMatch(True, f"{slot}: match")

    @staticmethod
    def _match_verb(rule_verb: str | None, request_verb: str) -> SlotMatch:
        if not rule_verb:
            return SlotMatch(True, "verb: (any)")
        if rule_verb == request_verb:
            return SlotMatch(True, f"verb: {request_verb}")
        return SlotMatch(False, f"verb: {request_verb!r} ≠ {rule_verb!r}")


# ── Conditions (CEL) ─────────────────────────────────────────────────────────
# Phase A: stateless `when:` expressions over {now, args}. CEL is non-Turing-
# complete (guaranteed to terminate) so it is safe to run in-process.

_CEL_ENV = None


def _cel_env():
    global _CEL_ENV
    if _CEL_ENV is None:
        import celpy
        _CEL_ENV = celpy.Environment()
    return _CEL_ENV


def _compile_cel(expr: str, rule_name: str):
    """Compile a `when:` CEL expression to a runnable program (raises on bad CEL)."""
    try:
        env = _cel_env()
        return env.program(env.compile(expr))
    except Exception as exc:
        raise ValueError(
            f"rule '{rule_name}': invalid when: expression {expr!r}: {exc}"
        ) from exc


def _eval_condition(program, context: dict) -> tuple[bool, str]:
    """Evaluate a compiled CEL program against {now, args}. Fail-closed: any
    error, timeout, or non-true result is a deny. Returns (ok, detail) where
    detail is "" on pass, "false" when the expression is simply false, or
    "error: …" when it couldn't be evaluated (e.g. an absent arg) — so denials
    can tell the agent exactly why."""
    import celpy
    now = dict(context.get("now") or {})
    raw_args = context.get("args") or {}
    # CEL is strict about int vs double, so coerce numeric args to double — rule
    # authors compare args with decimal literals (e.g. `args['volume'] < 50.0`).
    args: dict[str, Any] = {}
    for k, v in raw_args.items():
        if isinstance(v, bool):
            args[k] = v
        elif isinstance(v, int):
            args[k] = float(v)
        else:
            args[k] = v
    try:
        activation = {"now": celpy.json_to_cel(now), "args": celpy.json_to_cel(args)}
        result = program.evaluate(activation)
    except Exception as exc:
        return False, f"error: {str(exc)[:120]}"
    if isinstance(result, Exception):
        return False, f"error: {str(result)[:120]}"
    try:
        return (True, "") if bool(result) else (False, "false")
    except Exception as exc:
        return False, f"error: {str(exc)[:120]}"


# ── Attribute match helper ──────────────────────────────────────────────────


def _attr_matches(spec_value: Any, entity_value: Any) -> bool:
    """Return True if ``entity_value`` satisfies the rule spec's ``spec_value``.

    Semantics:
      - ``spec_value == '*'``: entity must have the attribute (any value)
      - ``entity_value is None``: no attribute present → miss (unless wildcard)
      - otherwise: normalize both to sets and require non-empty intersection
        (so single-vs-multi and multi-vs-multi all collapse to set overlap)
    """
    if spec_value == "*":
        return entity_value is not None
    if entity_value is None:
        return False
    spec_set = set(spec_value) if isinstance(spec_value, list) else {spec_value}
    entity_set = (
        set(entity_value) if isinstance(entity_value, list) else {entity_value}
    )
    return bool(spec_set & entity_set)


def _path_prefix_match(prefix: str, path: str) -> bool:
    """Segment-boundary prefix: a rule path matches itself and anything *under* it.
    ``/v1/users`` matches ``/v1/users`` and ``/v1/users/42`` but NOT ``/v1/usersX``.
    ``/`` (root) matches any absolute path. (No ``*`` glob — that's a later feature.)"""
    prefix = (prefix or "").rstrip("/") or "/"
    if prefix == "/":
        return path.startswith("/")
    return path == prefix or path.startswith(prefix + "/")


def _path_attr_matches(spec_value: Any, entity_value: Any) -> bool:
    """Path attribute matching: ``*`` = presence; otherwise segment-prefix (any of
    the rule's path values being a prefix of the request path is a match)."""
    if spec_value == "*":
        return entity_value is not None
    if not isinstance(entity_value, str):
        return False
    specs = spec_value if isinstance(spec_value, list) else [spec_value]
    return any(isinstance(s, str) and _path_prefix_match(s, entity_value) for s in specs)


# ── YAML helpers ────────────────────────────────────────────────────────────


def load_rules(yaml_str: str) -> list[Rule]:
    """Parse a ``rules:`` YAML document into a list of :class:`Rule` objects."""
    data = yaml.safe_load(yaml_str) or {}
    if not isinstance(data, dict):
        raise ValueError("rules YAML must be a mapping with a 'rules' key")
    entries = data.get("rules") or []
    if not isinstance(entries, list):
        raise ValueError("'rules' must be a list")
    return [Rule.from_dict(r) for r in entries]


def dump_rules(rules: list[Rule]) -> str:
    return yaml.safe_dump(
        {"rules": [r.to_dict() for r in rules]},
        sort_keys=False,
        default_flow_style=False,
    )
