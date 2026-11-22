"""A small JSON Schema validator for the subset used by the profile schema.

Why not a dependency? agentjail's runtime is stdlib only, and the profile
schema is a document we control. Supporting a documented subset (see
``SUPPORTED_KEYWORDS``) keeps the validator auditable -- roughly 300 lines --
instead of pulling a full implementation into the jail launcher, where every
extra dependency is extra supply-chain surface.

Unsupported keywords are rejected when the validator is constructed, so the
schema can never quietly mean more than this module enforces.
"""

from __future__ import annotations

import re
from typing import Any

__all__ = ["SUPPORTED_KEYWORDS", "SchemaDefinitionError", "SchemaValidator"]

#: JSON Schema keywords this validator understands. Anything else in a
#: validator schema position is a definition error.
SUPPORTED_KEYWORDS = frozenset(
    {
        "$comment",
        "$defs",
        "$id",
        "$ref",
        "$schema",
        "additionalProperties",
        "allOf",
        "anyOf",
        "const",
        "default",
        "description",
        "else",
        "enum",
        "if",
        "items",
        "maxItems",
        "maxLength",
        "maximum",
        "minItems",
        "minLength",
        "minimum",
        "not",
        "oneOf",
        "pattern",
        "properties",
        "required",
        "title",
        "then",
        "type",
        "uniqueItems",
    }
)

_ANNOTATION_KEYWORDS = frozenset(
    {
        "$comment",
        "$defs",
        "$id",
        "$schema",
        "default",
        "description",
        "title",
    }
)

_TYPE_NAMES = frozenset({"array", "boolean", "integer", "null", "number", "object", "string"})

#: Hard stop so a pathological document cannot produce unbounded output.
MAX_ERRORS = 100


class SchemaDefinitionError(ValueError):
    """The schema itself is outside the supported subset or malformed."""


def _json_type(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    raise SchemaDefinitionError(f"cannot determine JSON type of {type(value)!r}")


def _matches_type(value: Any, type_name: str) -> bool:
    actual = _json_type(value)
    if type_name == "number":
        return actual in {"integer", "number"}
    return actual == type_name


def _format_path(path: str, key: str) -> str:
    return f"{path}.{key}" if path else key


def _short(value: Any) -> str:
    text = repr(value)
    return text if len(text) <= 80 else text[:77] + "..."


class SchemaValidator:
    """Validates instances against a JSON Schema document (subset)."""

    def __init__(self, schema: dict[str, Any]) -> None:
        if not isinstance(schema, dict):
            raise SchemaDefinitionError("schema must be a JSON object")
        self._schema = schema
        self._check_definition(schema, "$")

    # -- definition checks -------------------------------------------------
    def _check_definition(self, schema: Any, where: str) -> None:
        if isinstance(schema, bool):
            return
        if not isinstance(schema, dict):
            raise SchemaDefinitionError(f"{where}: schema must be an object or boolean")
        unknown = set(schema) - SUPPORTED_KEYWORDS
        if unknown:
            raise SchemaDefinitionError(
                f"{where}: unsupported schema keyword(s): {', '.join(sorted(unknown))}"
            )
        type_value = schema.get("type")
        if type_value is not None:
            names = type_value if isinstance(type_value, list) else [type_value]
            for name in names:
                if name not in _TYPE_NAMES:
                    raise SchemaDefinitionError(f"{where}.type: unknown type {name!r}")
        pattern = schema.get("pattern")
        if pattern is not None:
            try:
                re.compile(pattern)
            except re.error as exc:  # pragma: no cover - schema typo only
                raise SchemaDefinitionError(f"{where}.pattern: {exc}") from exc
        if "required" in schema:
            required = schema["required"]
            if not isinstance(required, list) or not all(isinstance(i, str) for i in required):
                raise SchemaDefinitionError(f"{where}.required: must be a list of strings")
        if "properties" in schema:
            if not isinstance(schema["properties"], dict):
                raise SchemaDefinitionError(f"{where}.properties: must be an object")
            for key, subschema in schema["properties"].items():
                self._check_definition(subschema, _format_path(where, key))
        if "$defs" in schema:
            if not isinstance(schema["$defs"], dict):
                raise SchemaDefinitionError(f"{where}.$defs: must be an object")
            for key, subschema in schema["$defs"].items():
                self._check_definition(subschema, f"{where}/$defs/{key}")
        for keyword in ("items", "additionalProperties", "not", "if", "then", "else"):
            if keyword in schema:
                self._check_definition(schema[keyword], f"{where}.{keyword}")
        for keyword in ("allOf", "anyOf", "oneOf"):
            if keyword in schema:
                branches = schema[keyword]
                if not isinstance(branches, list) or not branches:
                    raise SchemaDefinitionError(f"{where}.{keyword}: must be a non-empty list")
                for index, subschema in enumerate(branches):
                    self._check_definition(subschema, f"{where}.{keyword}[{index}]")
        if "enum" in schema and not isinstance(schema["enum"], list):
            raise SchemaDefinitionError(f"{where}.enum: must be a list")

    # -- public API --------------------------------------------------------
    def errors(self, instance: Any) -> list[str]:
        """Return human-readable violations, each prefixed with its path."""
        found: list[str] = []
        self._validate(instance, self._schema, "", found)
        return found

    def is_valid(self, instance: Any) -> bool:
        return not self.errors(instance)

    # -- validation --------------------------------------------------------
    def _validate(self, instance: Any, schema: Any, path: str, errors: list[str]) -> None:
        if len(errors) >= MAX_ERRORS:
            return
        if schema is True:
            return
        if schema is False:
            errors.append(f"{path or '<root>'}: no value is allowed here")
            return
        if not isinstance(schema, dict):
            raise SchemaDefinitionError(f"validator at {path or '<root>'}: schema is not an object")

        ref = schema.get("$ref")
        if ref is not None:
            self._validate(instance, self._resolve(ref), path, errors)
            remaining = {
                key: value
                for key, value in schema.items()
                if key not in _ANNOTATION_KEYWORDS and key != "$ref"
            }
            if remaining:
                self._validate(instance, remaining, path, errors)
            return

        if "type" in schema:
            type_value = schema["type"]
            names = type_value if isinstance(type_value, list) else [type_value]
            if not any(_matches_type(instance, name) for name in names):
                errors.append(
                    f"{path or '<root>'}: expected {' or '.join(names)}, got {_json_type(instance)}"
                )
                return

        if "const" in schema and instance != schema["const"]:
            errors.append(f"{path or '<root>'}: must be {_short(schema['const'])}")
        if "enum" in schema and not any(
            instance == allowed and _json_type(instance) == _json_type(allowed)
            for allowed in schema["enum"]
        ):
            allowed = ", ".join(_short(item) for item in schema["enum"])
            errors.append(f"{path or '<root>'}: must be one of {allowed}, got {_short(instance)}")

        for subschema in schema.get("allOf", []):
            self._validate(instance, subschema, path, errors)

        if "anyOf" in schema and not any(
            self.is_valid_branch(instance, branch) for branch in schema["anyOf"]
        ):
            details = "; ".join(
                self._branch_hint(instance, branch, path) for branch in schema["anyOf"]
            )
            errors.append(f"{path or '<root>'}: does not match any allowed form ({details})")
        if "oneOf" in schema:
            matched = sum(1 for branch in schema["oneOf"] if self.is_valid_branch(instance, branch))
            if matched != 1:
                errors.append(
                    f"{path or '<root>'}: must match exactly one allowed form, matched {matched}"
                )
        if "not" in schema and self.is_valid_branch(instance, schema["not"]):
            errors.append(f"{path or '<root>'}: value is not allowed here")

        if "if" in schema:
            branch = "then" if self.is_valid_branch(instance, schema["if"]) else "else"
            if branch in schema:
                self._validate(instance, schema[branch], path, errors)

        if isinstance(instance, str):
            self._validate_string(instance, schema, path, errors)
        elif isinstance(instance, int | float) and not isinstance(instance, bool):
            if "minimum" in schema and instance < schema["minimum"]:
                errors.append(
                    f"{path or '<root>'}: must be >= {schema['minimum']}, got {instance!r}"
                )
            if "maximum" in schema and instance > schema["maximum"]:
                errors.append(
                    f"{path or '<root>'}: must be <= {schema['maximum']}, got {instance!r}"
                )
        elif isinstance(instance, list):
            self._validate_array(instance, schema, path, errors)
        elif isinstance(instance, dict):
            self._validate_object(instance, schema, path, errors)

    def _validate_string(
        self, instance: str, schema: dict[str, Any], path: str, errors: list[str]
    ) -> None:
        where = path or "<root>"
        if "minLength" in schema and len(instance) < schema["minLength"]:
            errors.append(f"{where}: must be at least {schema['minLength']} character(s) long")
        if "maxLength" in schema and len(instance) > schema["maxLength"]:
            errors.append(f"{where}: must be at most {schema['maxLength']} character(s) long")
        if "pattern" in schema and re.search(schema["pattern"], instance) is None:
            errors.append(f"{where}: {_short(instance)} does not match {schema['pattern']}")

    def _validate_array(
        self, instance: list[Any], schema: dict[str, Any], path: str, errors: list[str]
    ) -> None:
        where = path or "<root>"
        if "minItems" in schema and len(instance) < schema["minItems"]:
            errors.append(
                f"{where}: needs at least {schema['minItems']} item(s), got {len(instance)}"
            )
        if "maxItems" in schema and len(instance) > schema["maxItems"]:
            errors.append(
                f"{where}: allows at most {schema['maxItems']} item(s), got {len(instance)}"
            )
        if schema.get("uniqueItems") and len(instance) != len({repr(item) for item in instance}):
            errors.append(f"{where}: items must be unique")
        item_schema = schema.get("items")
        if item_schema is not None:
            for index, item in enumerate(instance):
                self._validate(item, item_schema, f"{path}[{index}]", errors)

    def _validate_object(
        self, instance: dict[str, Any], schema: dict[str, Any], path: str, errors: list[str]
    ) -> None:
        where = path or "<root>"
        for key in schema.get("required", []):
            if key not in instance:
                errors.append(f"{where}: missing required property {key!r}")
        properties = schema.get("properties", {})
        additional = schema.get("additionalProperties", True)
        for key, value in instance.items():
            child = _format_path(path, key)
            if key in properties:
                self._validate(value, properties[key], child, errors)
            elif additional is False:
                errors.append(f"{child}: unknown property (allowed: {_allowed_keys(properties)})")
            elif isinstance(additional, dict):
                self._validate(value, additional, child, errors)

    # -- helpers -----------------------------------------------------------
    def _resolve(self, ref: str) -> Any:
        if not ref.startswith("#"):
            raise SchemaDefinitionError(f"only local $ref values are supported, got {ref!r}")
        target: Any = self._schema
        pointer = ref[1:]
        if not pointer:
            return target
        if not pointer.startswith("/"):
            raise SchemaDefinitionError(f"unsupported $ref form {ref!r}")
        for raw in pointer[1:].split("/"):
            token = raw.replace("~1", "/").replace("~0", "~")
            if not isinstance(target, dict) or token not in target:
                raise SchemaDefinitionError(f"dangling $ref {ref!r}")
            target = target[token]
        return target

    def is_valid_branch(self, instance: Any, schema: Any) -> bool:
        """Validate without recording errors, for ``anyOf``/``if`` branches."""
        scratch: list[str] = []
        self._validate(instance, schema, "", scratch)
        return not scratch

    def _branch_hint(self, instance: Any, schema: Any, path: str) -> str:
        scratch: list[str] = []
        self._validate(instance, schema, path, scratch)
        return scratch[0] if scratch else "matches"


def _allowed_keys(properties: dict[str, Any]) -> str:
    keys = sorted(properties)
    return ", ".join(keys) if keys else "no properties"
