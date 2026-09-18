"""Validation against the JSON Schemas from the spec repo.

The schemas under `schemas/` are verbatim copies of `spec/schemas/*.json`, so
the service is self-contained in a container. `tests/test_spec_sync.py` fails
if the copies ever drift from the spec repo.

Relative `$ref`s (for example `observation.schema.json` from inside
`batch.schema.json`) resolve against each schema's `$id`, so registering every
schema under its own `$id` is enough to make the whole set self-referential
without any network access.
"""

from __future__ import annotations

import functools
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

SCHEMA_DIR = Path(__file__).resolve().parent.parent / "schemas"


@functools.lru_cache(maxsize=1)
def _registry() -> Registry:
    registry = Registry()
    for path in sorted(SCHEMA_DIR.glob("*.schema.json")):
        schema = json.loads(path.read_text(encoding="utf-8"))
        resource = Resource.from_contents(schema)
        registry = registry.with_resource(uri=schema["$id"], resource=resource)
    return registry


@functools.lru_cache(maxsize=None)
def validator(name: str) -> Draft202012Validator:
    """Return a cached validator for `name`, e.g. "envelope"."""
    path = SCHEMA_DIR / f"{name}.schema.json"
    schema = json.loads(path.read_text(encoding="utf-8"))
    return Draft202012Validator(schema, registry=_registry())


def schema_properties(name: str) -> set[str]:
    path = SCHEMA_DIR / f"{name}.schema.json"
    schema = json.loads(path.read_text(encoding="utf-8"))
    return set(schema.get("properties", {}))


class SchemaError(ValueError):
    """A document did not match its schema. `detail` is safe to return."""

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


def validate(name: str, document: Any) -> None:
    """Raise SchemaError with a short, non-revealing message on failure."""
    errors = sorted(validator(name).iter_errors(document), key=lambda e: list(e.path))
    if not errors:
        return
    first = errors[0]
    location = "/".join(str(p) for p in first.absolute_path) or "(root)"
    raise SchemaError(f"{location}: {first.message}")
