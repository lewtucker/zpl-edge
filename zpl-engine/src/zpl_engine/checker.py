"""zpl_checker — adapter between live MCP calls and the vendored ZPL engine.

The engine (mcp_defender.zpl) matches by *class*; a live MCP call arrives as
plain strings: (user, agent_id, tool, args, service). This module bridges the
two:

  compile_rules(zpl_text)  → CompiledRuleSet   (parse once, at bind time)
  check(crs, user=…, agent_id=…, tool=…, args=…, service=…) → Decision

Entity resolution, in order:
  1. Declared — a `Declare <name> as a <class> with …` statement in the rule
     set binds that identity to a class + attrs (how a lab manager grants a
     role to a person or agent).
  2. Inferred — the most specific Define'd class whose fixed-value attributes
     are satisfied by the call's attrs (a call with tool:control_run is an
     instance of any service class defined `with tool:control_run`). Depth
     wins; more fixed attrs breaks ties. Only fixed values participate —
     required-but-unvalued attrs do not block inference.
  3. Bare root — an entity of the built-in root class, which matches only
     rules that don't constrain that slot. Unknown identities therefore fall
     to default deny under any subject-constrained rule set.

Verdict: Never rules first match → deny; Allow first match → allow;
no match → deny (zero trust).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .zpl import (
    ROOT_CLASSES, CheckRequest, ClassSchema, ClassSchemaError, Entity, Rule,
    ZPLEngine, parse,
)

VERB = "access"  # default verb for MCP tool calls (verb-agnostic)

# HTTP methods map to coarse ZPL verbs so egress rules read as intent, not mechanics:
#   Allow X to read …      Never allow X to delete …
# DELETE stays a distinct verb — it's the dangerous one you'll want to call out.
# Unknown/odd methods fall back to "access" (won't satisfy a read/write/delete rule).
_METHOD_VERBS = {
    "GET": "read", "HEAD": "read", "OPTIONS": "read",
    "POST": "write", "PUT": "write", "PATCH": "write",
    "DELETE": "delete",
}


def verb_for_method(method: str) -> str:
    return _METHOD_VERBS.get((method or "").strip().upper(), "access")


class ZPLCompileError(ValueError):
    """Raised when a rule set fails to parse or its schema is inconsistent."""


@dataclass
class CompiledRuleSet:
    engine: ZPLEngine
    schema: ClassSchema
    entities: dict[str, dict]            # declared name → {class_name, attributes}
    fixed_attrs: dict[str, dict]         # class → {attr: fixed value(s)}
    rule_count: int = 0


@dataclass
class Decision:
    verdict: str                         # "allow" | "deny"
    rule_name: str | None = None         # matched rule, None = default deny
    reason: str = ""
    trace: list = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return self.verdict == "allow"


def _ci_lower(x):
    """Lowercase a string token for case-insensitive matching; pass non-strings through."""
    return x.lower() if isinstance(x, str) else x


def _fold_value(attr_name: str, v):
    """Fold an attribute value for matching — EXCEPT HTTP `path` (case-sensitive,
    segment-matched). Handles scalar and set (list) values."""
    if attr_name == "path":
        return v
    if isinstance(v, (list, tuple)):
        return [_ci_lower(x) for x in v]
    return _ci_lower(v)


def _casefold_parsed(parsed: dict) -> dict:
    """Lowercase all MATCH tokens — class names, attribute names + values, entity names — so
    matching is case-insensitive (the RFC-15.5 BNF leaves case unspecified). Deliberately does
    NOT touch `when:` conditions (CEL is case-sensitive), rule display names, or `path` values.
    Storage/display are unaffected — this only folds the compiled match representation; the call
    side is folded the same way in check()."""
    def fold_spec_attrs(attrs):
        return {_ci_lower(k): _fold_value(_ci_lower(k), val) for k, val in (attrs or {}).items()}

    def fold_class_attrs(attrs):
        out = {}
        for k, spec in (attrs or {}).items():
            s, lk = dict(spec), _ci_lower(k)
            if "value" in s:
                s["value"] = _fold_value(lk, s["value"])
            if "values" in s:
                s["values"] = _fold_value(lk, list(s["values"]))
            out[lk] = s
        return out

    def fold_spec(spec):
        if not spec:
            return spec
        s = dict(spec)
        for key in ("class", "name"):
            if key in s:
                s[key] = _ci_lower(s[key])
        if "attrs" in s:
            s["attrs"] = fold_spec_attrs(s["attrs"])
        return s

    for c in parsed.get("classes", []):
        c["class"] = _ci_lower(c.get("class"))
        if c.get("parent"):
            c["parent"] = _ci_lower(c["parent"])
        if c.get("aka"):
            c["aka"] = _ci_lower(c["aka"])
        c["attributes"] = fold_class_attrs(c.get("attributes"))
    for e in parsed.get("entities", []):
        e["name"] = _ci_lower(e.get("name"))
        e["class_name"] = _ci_lower(e.get("class_name"))
        e["attributes"] = fold_spec_attrs(e.get("attributes"))
    for r in parsed.get("rules", []):
        for slot in ("subject", "accessor_endpoint", "object", "server_endpoint"):
            if r.get(slot):
                r[slot] = fold_spec(r[slot])
    return parsed


def compile_rules(zpl_text: str) -> CompiledRuleSet:
    """Parse a ZPL rule set and build an engine. Raises ZPLCompileError."""
    try:
        parsed = _casefold_parsed(parse(zpl_text))   # case-insensitive matching (see _casefold_parsed)
    except Exception as exc:
        raise ZPLCompileError(f"ZPL parse error: {exc}") from exc

    try:
        schema = ClassSchema(ROOT_CLASSES + parsed["classes"])
    except ClassSchemaError as exc:
        raise ZPLCompileError(f"ZPL class error: {exc}") from exc

    try:
        rules = [Rule.from_dict(r) for r in parsed["rules"]]
    except ValueError as exc:
        raise ZPLCompileError(f"ZPL rule error: {exc}") from exc

    # Pre-extract each class's fixed-value attributes for membership inference.
    fixed: dict[str, dict] = {}
    for cls in parsed["classes"]:
        name = cls["class"]
        out = {}
        for attr, spec in (schema.resolve(name) or {}).items():
            if "value" in spec:
                out[attr] = spec["value"]
            elif "values" in spec:
                out[attr] = list(spec["values"])
        fixed[name] = out

    entities = {e["name"]: e for e in parsed.get("entities", [])}
    # Declares are stored verbatim by the parser, so "Declare Lew as a user"
    # lands in class 'user' while rule specs alias it to the root 'users' —
    # the identity would silently match nothing. Normalize via the builtin
    # aliases, but only when the literal class is unknown (a Define'd class
    # that happens to share an alias name keeps priority).
    from .zpl.zpl_parser import _BUILTIN_ALIASES
    for ent in entities.values():
        cls = ent["class_name"]
        if not schema.has(cls):
            alias = _BUILTIN_ALIASES.get(cls.lower())
            if alias and schema.has(alias):
                ent["class_name"] = alias
    try:
        engine = ZPLEngine(rules, schema)   # compiles each rule's when: CEL up front
    except ValueError as exc:
        raise ZPLCompileError(f"ZPL condition error: {exc}") from exc
    return CompiledRuleSet(
        engine=engine,
        schema=schema,
        entities=entities,
        fixed_attrs=fixed,
        rule_count=len(rules),
    )


def _fixed_match(fixed: dict, attrs: dict) -> bool:
    for k, v in fixed.items():
        have = attrs.get(k)
        if isinstance(v, list):
            if have not in v:
                return False
        elif have != v:
            return False
    return True


def _infer_class(crs: CompiledRuleSet, root: str, attrs: dict,
                 exclude_subtree: str | None = None) -> str | None:
    """Most specific class under `root` whose fixed attrs the call satisfies."""
    best: tuple[int, int, str] | None = None
    for name, fixed in crs.fixed_attrs.items():
        try:
            if not crs.schema.is_subclass(name, root):
                continue
            if exclude_subtree and crs.schema.is_subclass(name, exclude_subtree):
                continue
        except Exception:
            continue
        if not _fixed_match(fixed, attrs):
            continue
        depth = len(crs.schema.ancestors(name))
        key = (depth, len(fixed), name)
        if best is None or key > best:
            best = key
    return best[2] if best else None


def _resolve(crs: CompiledRuleSet, name: str, root: str, attrs: dict,
             exclude_subtree: str | None = None) -> Entity:
    """Declared entity → inferred class → bare root (see module docstring)."""
    declared = crs.entities.get(name)
    if declared:
        merged = {"name": name, **(declared.get("attributes") or {}), **attrs}
        return Entity(class_name=declared["class_name"], name=name, attrs=merged)
    inferred = _infer_class(crs, root, {"name": name, **attrs}, exclude_subtree)
    return Entity(class_name=inferred or root, name=name, attrs={"name": name, **attrs})


def _unguarded_arg_refs(expr: str) -> list[str]:
    """Arg keys a `when:` reads (`args['k']` or `args.k`) that have no presence
    guard (`'k' in args` or `has(args.k)`) in the same expression. Advisory only —
    a regex heuristic, not a CEL parse; over-reports a guard written in an exotic
    form rather than under-reporting a real footgun."""
    import re
    refs = set(re.findall(r"args\[\s*['\"]([^'\"]+)['\"]\s*\]", expr))
    refs |= set(re.findall(r"args\.([A-Za-z_]\w*)", expr))
    guarded = set(re.findall(r"['\"]([^'\"]+)['\"]\s+in\s+args\b", expr))
    guarded |= set(re.findall(r"has\(\s*args\.([A-Za-z_]\w*)\s*\)", expr))
    guarded |= set(re.findall(r"has\(\s*args\[\s*['\"]([^'\"]+)['\"]\s*\]\s*\)", expr))
    return sorted(refs - guarded)


def lint_rules(zpl_text: str, crs: CompiledRuleSet | None = None,
               known_tools: list[str] | None = None) -> list[str]:
    """Advisory warnings for the traps that compile fine but never match
    (or match everything). Returned alongside compile results on save.

    known_tools: the guard's learned tool names, when available — enables the
    semantic check that a service class's tool: value is a real upstream tool.
    """
    import re
    warnings: list[str] = []
    if crs is None:
        crs = compile_rules(zpl_text)  # caller handles ZPLCompileError
    schema = crs.schema
    known = set(known_tools or [])

    # Statements that vanished — usually a missing terminating period.
    stmt_lines = sum(
        1 for line in zpl_text.splitlines()
        if re.match(r"\s*(allow|never|define|declare)\b", line, re.IGNORECASE)
    )
    parsed = crs.rule_count + len(crs.fixed_attrs) + len(crs.entities)
    if stmt_lines > parsed:
        warnings.append(
            f"{stmt_lines - parsed} statement(s) did not parse — "
            "check for missing terminating periods."
        )

    # Class-level traps.
    for name, fixed in crs.fixed_attrs.items():
        try:
            kind = schema.kind_of(name)
        except Exception:
            continue
        if kind == "services":
            if not fixed:
                warnings.append(
                    f"service class '{name}' has no fixed attributes — it matches EVERY call. "
                    f"Pin it to a tool: Define {name} as a service with tool:<tool-name>."
                )
            elif "tool" not in fixed:
                warnings.append(
                    f"service class '{name}' has no tool: attribute — it cannot be tied to a "
                    f"specific MCP tool (calls carry tool:<name> plus their arguments)."
                )
            elif known:
                vals = fixed["tool"] if isinstance(fixed["tool"], list) else [fixed["tool"]]
                for v in vals:
                    if v not in known:
                        warnings.append(
                            f"service class '{name}': tool:{v} is not a tool on this guard's "
                            f"upstream — rules referencing it will never match. "
                            f"Known tools: {', '.join(sorted(known)[:8])}"
                            f"{'…' if len(known) > 8 else ''}."
                        )
        elif kind == "users" and not fixed and name not in crs.entities:
            warnings.append(
                f"user class '{name}' has no fixed attributes — ANY identity matches it. "
                f"Pin it: Define {name} as a user with name:{name}."
            )
        elif kind == "endpoints" and not fixed and not schema.is_subclass(name, "servers"):
            warnings.append(
                f"endpoint class '{name}' has no fixed attributes — any agent matches it. "
                f"Pin it: Define {name} as an endpoint with name:{name}."
            )

    # Rule-level traps.
    from .zpl.zpl_parser import _VERBS
    for i, rule in enumerate(crs.engine.rules, 1):
        # when: that reads an arg without a presence guard fails closed (deny)
        # on any call that omits that arg — easy to do with an optional arg.
        for key in _unguarded_arg_refs(getattr(rule, "condition", None) or ""):
            warnings.append(
                f"rule {i} ({rule.name}): when: reads args['{key}'] without a presence "
                f"guard — if '{key}' is optional, a call that omits it errors and is "
                f"denied (fail-closed). Guard it, e.g. "
                f"\"!('{key}' in args) || args['{key}'] …\"."
            )
        if rule.verb and rule.verb.lower() not in _VERBS:
            warnings.append(
                f"rule {i} ({rule.name}): unknown verb '{rule.verb}' — "
                f"calls are checked with verb 'access', so this rule will never match. "
                f"Valid verbs: {', '.join(sorted(_VERBS))}."
            )
        for slot, spec in (("subject", rule.subject),
                           ("agent", rule.accessor_endpoint),
                           ("object", rule.object),
                           ("server", rule.server_endpoint)):
            if spec is None or not spec.class_name:
                continue
            if not schema.has(spec.class_name):
                warnings.append(
                    f"rule {i} ({rule.name}): {slot} references undefined class "
                    f"'{spec.class_name}' — the rule will never match."
                )
            elif slot == "server" and not schema.is_subclass(spec.class_name, "servers"):
                warnings.append(
                    f"rule {i} ({rule.name}): '{spec.class_name}' fills the server slot "
                    f"(after the final 'on') but is not defined as a server — "
                    f"use: Define {spec.class_name} as a server with name:{spec.class_name}."
                )

    # Identity-level traps.
    for name, ent in crs.entities.items():
        if not schema.has(ent["class_name"]):
            warnings.append(
                f"Declare {name}: class '{ent['class_name']}' is not defined — "
                f"this identity matches no rule. Define the class first, or use "
                f"one of users/endpoints/services/servers."
            )

    # Subject/agent attribute filters match Declare-level attributes only
    # (a class's fixed attrs are not inherited onto declared identities, and
    # calls never carry identity attributes). Warn when nothing in the rule
    # set can ever satisfy one.
    declared_attr_keys: set[str] = set()
    for ent in crs.entities.values():
        declared_attr_keys.update((ent.get("attributes") or {}).keys())
    for i, rule in enumerate(crs.engine.rules, 1):
        for slot, spec in (("subject", rule.subject),
                           ("agent", rule.accessor_endpoint)):
            if spec is None or not spec.attrs:
                continue
            cls_attrs = {}
            if spec.class_name and schema.has(spec.class_name):
                cls_attrs = schema.resolve(spec.class_name) or {}
            for attr in spec.attrs:
                if attr == "name" or attr in declared_attr_keys or attr in cls_attrs:
                    continue
                warnings.append(
                    f"rule {i} ({rule.name}): {slot} filter '{attr}:' is matched "
                    f"against Declare-level attributes, and no Declare statement "
                    f"carries '{attr}' — identity attributes come from Declare "
                    f"lines, not from the call."
                )
    return warnings


def check(crs: CompiledRuleSet, *, user: str, agent_id: str, tool: str,
          args: dict | None = None, service: str = "", verb: str = VERB, now=None,
          subject_attrs: dict | None = None) -> Decision:
    """Evaluate one call against a compiled rule set.

    `verb` defaults to "access" (MCP tool calls are verb-agnostic); HTTP egress
    passes read/write/delete (see verb_for_method) so rules can say `to read …`.
    `now` (a datetime, default = current local time) and the raw `args` form the
    context for rule `when:` conditions — see docs/architecture/zpl-conditions.md.
    """
    # Encode everything exactly as the analyzer does when writing rules —
    # names via zpl_token (idempotent, so pre-tokenized callers are fine),
    # values via _zpl_value (True → "true") — or rules never match. The
    # structural "tool" attr is set last so an arg that happens to be named
    # "tool" can never corrupt class inference.
    from .helpers import _zpl_value, zpl_token
    # Names via zpl_token (idempotent), then lowercased to match the case-folded ruleset
    # (see _casefold_parsed). Values via _zpl_value then folded (set/scalar), EXCEPT `path`.
    user = _ci_lower(zpl_token(user))
    agent_id = _ci_lower(zpl_token(agent_id))
    service = _ci_lower(zpl_token(service)) if service else ""
    tool_l = _ci_lower(tool)
    call_attrs = {**{(lk := _ci_lower(zpl_token(k))): _fold_value(lk, _zpl_value(v))
                     for k, v in (args or {}).items()},
                  "tool": tool_l}

    # Subject attributes (roles/groups/department/…) resolved by the caller from the
    # principal layer (P1). list values (e.g. roles) pass through for the engine's set match.
    # Empty = today's behavior (name-only subject → only name/class rules match).
    sattrs = {(lk := _ci_lower(zpl_token(k))): _fold_value(
                  lk, [_zpl_value(x) for x in v] if isinstance(v, (list, tuple)) else _zpl_value(v))
              for k, v in (subject_attrs or {}).items()}
    subject = _resolve(crs, user, "users", sattrs)
    obj_class = _infer_class(crs, "services", call_attrs)
    obj = Entity(class_name=obj_class or "services", name=tool_l, attrs=call_attrs)
    accessor = _resolve(crs, agent_id, "endpoints", {}, exclude_subtree="servers")
    server = _resolve(crs, service, "servers", {}) if service else None

    from datetime import datetime
    _now = now or datetime.now()
    context = {
        "now": {
            "hour": _now.hour, "minute": _now.minute,
            "weekday": _now.weekday(),   # 0 = Monday .. 6 = Sunday
            "day": _now.day, "month": _now.month, "year": _now.year,
        },
        "args": dict(args or {}),   # raw args for CEL (not the tokenized call_attrs)
    }

    result = crs.engine.evaluate(CheckRequest(
        subject=subject, object=obj, verb=verb,
        accessor_endpoint=accessor, server_endpoint=server,
        context=context,
    ))
    if result.rule_name:
        reason = f"matched rule: {result.rule_name}"
    else:
        reason = "no matching allow rule (default deny)"
        # Instructive denial: if an Allow rule matched every spec and ONLY its
        # when: condition failed, say so — the agent/operator sees exactly which
        # rule's condition blocked the call rather than a generic default deny.
        for rt in result.trace:
            if rt.result != "allow" or rt.matched:
                continue
            failed = [s for s, sm in rt.slot_matches.items() if not sm.matched]
            if failed == ["condition"]:
                cond = rt.slot_matches["condition"].reason   # "when:'…' → false|error: …"
                reason = f"denied by condition on rule '{rt.rule_name}': {cond}"
                break
    return Decision(
        verdict=result.verdict,
        rule_name=result.rule_name,
        reason=reason,
        trace=[t.to_dict() for t in result.trace],
    )


def service_reachable(crs: CompiledRuleSet, *, user: str, agent_id: str,
                      service: str, subject_attrs: dict | None = None) -> bool:
    """True iff some Allow rule grants this principal ANY access on `service`.

    Reachability deliberately ignores the object (tool), verb, and `when:` — it asks
    only "is this (subject, agent, roles) permitted to reach this server at all?".
    It gates MCP transport/handshake traffic (SSE open, `initialize`, `tools/list`)
    so an *authorized* server's session can start (it has at least one allow rule on
    that host) while an *unauthorized* one — no rule naming it — is blocked outright.
    Per-tool control is the separate `check()` on `tools/call`.

    Matching reuses the engine's own spec matcher (`_match_rule`), so roles, classes,
    and wildcards stay identical to `check()` — no policy logic is duplicated here.
    Iterates every Allow rule (no short-circuit), so a leading Never can't hide one."""
    if not service:
        return False
    from datetime import datetime
    from .helpers import _zpl_value, zpl_token
    user = _ci_lower(zpl_token(user))
    agent_id = _ci_lower(zpl_token(agent_id))
    service = _ci_lower(zpl_token(service))
    sattrs = {(lk := _ci_lower(zpl_token(k))): _fold_value(
                  lk, [_zpl_value(x) for x in v] if isinstance(v, (list, tuple)) else _zpl_value(v))
              for k, v in (subject_attrs or {}).items()}
    subject = _resolve(crs, user, "users", sattrs)
    accessor = _resolve(crs, agent_id, "endpoints", {}, exclude_subtree="servers")
    server = _resolve(crs, service, "servers", {})
    # Object/verb are ignored for reachability; placeholders keep _match_rule happy.
    obj = Entity(class_name="services", name="*", attrs={"tool": "*"})
    _now = datetime.now()
    context = {"now": {"hour": _now.hour, "minute": _now.minute, "weekday": _now.weekday(),
                       "day": _now.day, "month": _now.month, "year": _now.year}, "args": {}}
    req = CheckRequest(subject=subject, object=obj, verb=VERB,
                       accessor_endpoint=accessor, server_endpoint=server, context=context)
    eng = crs.engine
    for rule in eng.rules:
        if rule.result != "allow":
            continue
        sm = eng._match_rule(rule, req).slot_matches
        if (sm["subject"].matched and sm["accessor_endpoint"].matched
                and sm["server_endpoint"].matched):
            return True
    return False
