# Vendored from ZPR-Policy-maker-v2 (commit 3e818aa, 2026-05-15)
# src/server/ — evolves independently here; do not sync blindly.
"""ZPL RFC-15.5 class hierarchy loader and resolver.

Loads a class schema from YAML (see docs/RFC_classes.yaml), validates it, and
provides read-only access to the class graph plus attribute inheritance
resolution.

Schema shape::

    classes:
      - id:                  # UUID; empty in class definitions
        class: employee      # ZPL class name (required, unique)
        parent: users        # parent class name; null for the three built-in roots
        builtin: true        # optional; marks system classes
        aka: employees       # optional single alias
        description: ...
        attributes:
          name:
            type: single | multi | tag
            values: [...]    # single only — enumerated allowed values
            value: <string>  # single only — fixed inherited value (subclass restriction)
            optional: true   # tag only — attribute may be absent

The three built-in roots (``users``, ``endpoints``, ``services``) must exist
with ``parent: null`` and ``builtin: true``. If ``servers`` is present it must
be a direct subclass of ``endpoints``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Iterator

import yaml

BUILTIN_ROOTS: tuple[str, ...] = ("users", "endpoints", "services")
PREDEFINED_SERVERS_PARENT: str = "endpoints"
VALID_ATTR_TYPES: tuple[str, ...] = ("single", "multi", "tag")


class ClassSchemaError(ValueError):
    """Raised when a class schema fails validation."""


class ClassSchema:
    """Immutable view over a loaded class hierarchy."""

    def __init__(self, classes: list[dict]):
        self._raw: dict[str, dict] = {}
        self._children: dict[str, list[str]] = {}
        self._resolved_cache: dict[str, dict[str, dict]] = {}
        self._aka_index: dict[str, str] = {}  # alias → canonical name
        self._load(classes)
        self._validate()
        self._build_children_index()
        self._build_aka_index()

    # ── construction ─────────────────────────────────────────────────────────

    @classmethod
    def from_yaml(cls, path: str | Path) -> "ClassSchema":
        with open(path) as f:
            data = yaml.safe_load(f)
        return cls.from_dict(data)

    @classmethod
    def from_yaml_string(cls, text: str) -> "ClassSchema":
        return cls.from_dict(yaml.safe_load(text))

    @classmethod
    def from_dict(cls, data: Any) -> "ClassSchema":
        if not isinstance(data, dict):
            raise ClassSchemaError("Schema must be a mapping with a 'classes' key")
        classes = data.get("classes")
        if classes is None:
            raise ClassSchemaError("Schema is missing the 'classes' key")
        if not isinstance(classes, list):
            raise ClassSchemaError("'classes' must be a list")
        return cls(classes)

    # ── loading & validation ─────────────────────────────────────────────────

    def _load(self, classes: list[dict]) -> None:
        for idx, entry in enumerate(classes):
            if not isinstance(entry, dict):
                raise ClassSchemaError(f"Class at index {idx} is not a mapping")
            name = entry.get("class")
            if not name:
                raise ClassSchemaError(
                    f"Class at index {idx} is missing the required 'class' field"
                )
            if not isinstance(name, str):
                raise ClassSchemaError(
                    f"Class at index {idx} has non-string 'class': {name!r}"
                )
            if name in self._raw:
                raise ClassSchemaError(f"Duplicate class name: {name!r}")
            self._raw[name] = entry

    def _validate(self) -> None:
        for root in BUILTIN_ROOTS:
            if root not in self._raw:
                raise ClassSchemaError(
                    f"Missing required built-in root class: {root!r}"
                )
            entry = self._raw[root]
            if entry.get("parent") is not None:
                raise ClassSchemaError(
                    f"Built-in root {root!r} must have parent: null "
                    f"(got {entry.get('parent')!r})"
                )
            if not entry.get("builtin"):
                raise ClassSchemaError(
                    f"Built-in root {root!r} must have builtin: true"
                )

        if "servers" in self._raw:
            parent = self._raw["servers"].get("parent")
            if parent != PREDEFINED_SERVERS_PARENT:
                raise ClassSchemaError(
                    f"'servers' must have parent: {PREDEFINED_SERVERS_PARENT!r} "
                    f"(got {parent!r})"
                )

        for name, entry in self._raw.items():
            self._validate_entry(name, entry)
            self._check_no_cycle(name)

    def _validate_entry(self, name: str, entry: dict) -> None:
        parent = entry.get("parent")
        if parent is not None:
            if not isinstance(parent, str):
                raise ClassSchemaError(
                    f"Class {name!r} has non-string parent: {parent!r}"
                )
            if parent == name:
                raise ClassSchemaError(f"Class {name!r} cannot be its own parent")
            if parent not in self._raw:
                raise ClassSchemaError(
                    f"Class {name!r} references unknown parent: {parent!r}"
                )

        attributes = entry.get("attributes") or {}
        if not isinstance(attributes, dict):
            raise ClassSchemaError(
                f"Class {name!r} 'attributes' must be a mapping "
                f"(got {type(attributes).__name__})"
            )
        for attr_name, spec in attributes.items():
            self._validate_attribute(name, attr_name, spec)

    def _validate_attribute(
        self, class_name: str, attr_name: str, spec: Any
    ) -> None:
        if not isinstance(spec, dict):
            raise ClassSchemaError(
                f"Class {class_name!r} attribute {attr_name!r} must be a mapping"
            )
        attr_type = spec.get("type")
        if attr_type not in VALID_ATTR_TYPES:
            raise ClassSchemaError(
                f"Class {class_name!r} attribute {attr_name!r}: invalid type "
                f"{attr_type!r} (must be one of {VALID_ATTR_TYPES})"
            )
        if attr_type == "tag":
            if "value" in spec or "values" in spec:
                raise ClassSchemaError(
                    f"Class {class_name!r} attribute {attr_name!r}: "
                    f"tags cannot have 'value' or 'values'"
                )
        if attr_type == "multi" and "value" in spec:
            raise ClassSchemaError(
                f"Class {class_name!r} attribute {attr_name!r}: "
                f"multi-valued cannot have fixed 'value'"
            )
        values = spec.get("values")
        if values is not None and not isinstance(values, list):
            raise ClassSchemaError(
                f"Class {class_name!r} attribute {attr_name!r}: "
                f"'values' must be a list"
            )

    def _check_no_cycle(self, start: str) -> None:
        seen: list[str] = []
        current: str | None = start
        while current is not None:
            if current in seen:
                chain = " → ".join(seen + [current])
                raise ClassSchemaError(
                    f"Cycle detected in class hierarchy: {chain}"
                )
            seen.append(current)
            current = self._raw[current].get("parent")

    def _build_children_index(self) -> None:
        for name in self._raw:
            self._children[name] = []
        for name, entry in self._raw.items():
            parent = entry.get("parent")
            if parent is not None:
                self._children[parent].append(name)

    def _build_aka_index(self) -> None:
        for name, entry in self._raw.items():
            aka = entry.get("aka")
            if aka and isinstance(aka, str) and aka not in self._raw:
                self._aka_index[aka] = name

    # ── queries ──────────────────────────────────────────────────────────────

    def names(self) -> list[str]:
        """Return all class names in declaration order."""
        return list(self._raw.keys())

    def builtins(self) -> list[str]:
        """Return names of all classes flagged builtin: true."""
        return [n for n, e in self._raw.items() if e.get("builtin")]

    def canonical(self, name: str) -> str:
        """Return the canonical class name, resolving an aka alias if needed."""
        if name in self._raw:
            return name
        if name in self._aka_index:
            return self._aka_index[name]
        raise KeyError(name)

    def aka(self, name: str) -> str | None:
        """Return the aka alias for this class, or None if none defined."""
        return self._raw.get(self.canonical(name), {}).get("aka")

    def has(self, name: str) -> bool:
        return name in self._raw or name in self._aka_index

    def get(self, name: str) -> dict:
        """Return the raw class definition (non-merged), resolving aka aliases.

        Raises:
            KeyError: if no such class or alias.
        """
        return self._raw[self.canonical(name)]

    def parent(self, name: str) -> str | None:
        return self.get(name).get("parent")

    def children(self, name: str) -> list[str]:
        """Return immediate children of this class."""
        return list(self._children[self.canonical(name)])

    def ancestors(self, name: str) -> list[str]:
        """Return ancestors from immediate parent up to root (exclusive of self)."""
        out: list[str] = []
        current = self.parent(name)
        while current is not None:
            out.append(current)
            current = self.parent(current)
        return out

    def descendants(self, name: str) -> list[str]:
        """Return all transitive descendants (breadth-first)."""
        canon = self.canonical(name)
        out: list[str] = []
        queue = list(self._children[canon])
        while queue:
            current = queue.pop(0)
            out.append(current)
            queue.extend(self._children[current])
        return out

    def is_subclass(self, child: str, ancestor: str) -> bool:
        """True if ``child`` equals or descends from ``ancestor``."""
        child = self.canonical(child)
        ancestor = self.canonical(ancestor)
        if child == ancestor:
            return True
        return ancestor in self.ancestors(child)

    def kind_of(self, name: str) -> str:
        """Return the built-in root (``users``, ``endpoints``, or ``services``) for ``name``."""
        name = self.canonical(name)
        chain = [name] + self.ancestors(name)
        root = chain[-1]
        if root not in BUILTIN_ROOTS:
            raise ClassSchemaError(
                f"Class {name!r} does not descend from a built-in root "
                f"(chain: {' → '.join(chain)})"
            )
        return root

    def resolve(self, name: str) -> dict[str, dict]:
        """Return the fully merged attribute dict for ``name``.

        Walks root-to-leaf; subclass definitions override parent definitions
        for attributes with the same name. The returned dict is cached but
        callers get a fresh copy on each call.
        """
        name = self.canonical(name)
        if name not in self._resolved_cache:
            chain = list(reversed([name] + self.ancestors(name)))
            merged: dict[str, dict] = {}
            for cls_name in chain:
                attrs = self._raw[cls_name].get("attributes") or {}
                for attr_name, spec in attrs.items():
                    merged[attr_name] = _deepcopy_attr(spec)
            self._resolved_cache[name] = merged
        # Return a shallow copy of the cache entry with deep-copied specs
        cached = self._resolved_cache[name]
        return {k: _deepcopy_attr(v) for k, v in cached.items()}

    # ── iteration ────────────────────────────────────────────────────────────

    def __iter__(self) -> Iterator[str]:
        return iter(self._raw)

    def __len__(self) -> int:
        return len(self._raw)

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and (name in self._raw or name in self._aka_index)

    def __repr__(self) -> str:
        return f"ClassSchema(classes={len(self._raw)})"


def _deepcopy_attr(spec: dict) -> dict:
    """Shallow-copy an attribute spec, duplicating list/dict values one level deep."""
    out: dict[str, Any] = {}
    for k, v in spec.items():
        if isinstance(v, list):
            out[k] = list(v)
        elif isinstance(v, dict):
            out[k] = dict(v)
        else:
            out[k] = v
    return out
