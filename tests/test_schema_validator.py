"""Unit tests for the JSON Schema subset validator."""

from __future__ import annotations

import pytest

from agentjail.schema import SchemaDefinitionError, SchemaValidator


def errors(schema: dict, instance: object) -> list[str]:
    return SchemaValidator(schema).errors(instance)


def test_type_mismatch_is_specific() -> None:
    found = errors(
        {"type": "object", "required": ["a"], "properties": {"a": {"type": "string"}}}, []
    )
    assert found == ["<root>: expected object, got array"]


def test_missing_required_property_reports_path_and_name() -> None:
    schema = {
        "type": "object",
        "required": ["network"],
        "properties": {"network": {"type": "object", "required": ["mode"]}},
    }
    assert errors(schema, {}) == ["<root>: missing required property 'network'"]
    assert errors(schema, {"network": {}}) == ["network: missing required property 'mode'"]


def test_additional_properties_false_lists_allowed_keys() -> None:
    schema = {
        "type": "object",
        "additionalProperties": False,
        "properties": {"a": {"type": "string"}, "b": {"type": "integer"}},
    }
    found = errors(schema, {"c": 1})
    assert found == ["c: unknown property (allowed: a, b)"]


def test_pattern_and_length_and_enum() -> None:
    schema = {
        "type": "object",
        "properties": {
            "digest": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
            "mode": {"enum": ["none", "allowlist"]},
            "name": {"type": "string", "minLength": 2, "maxLength": 4},
        },
    }
    found = errors(schema, {"digest": "sha256:xyz", "mode": "both", "name": "x"})
    assert len(found) == 3
    assert found[0].startswith("digest: 'sha256:xyz' does not match")
    assert found[1].startswith("mode: must be one of")
    assert found[2] == "name: must be at least 2 character(s) long"


def test_numeric_bounds_and_array_items() -> None:
    schema = {
        "type": "object",
        "properties": {
            "port": {"type": "integer", "minimum": 1, "maximum": 65535},
            "hosts": {"type": "array", "items": {"type": "string"}, "minItems": 1},
        },
    }
    assert errors(schema, {"port": 0}) == ["port: must be >= 1, got 0"]
    assert errors(schema, {"port": True}) == ["port: expected integer, got boolean"]
    assert errors(schema, {"hosts": []}) == ["hosts: needs at least 1 item(s), got 0"]
    assert errors(schema, {"hosts": ["a", 2]}) == ["hosts[1]: expected string, got integer"]


def test_local_ref_and_anyof() -> None:
    schema = {
        "type": "object",
        "properties": {"size": {"$ref": "#/$defs/size"}},
        "$defs": {"size": {"anyOf": [{"type": "integer"}, {"type": "string"}]}},
    }
    validator = SchemaValidator(schema)
    assert validator.is_valid({"size": "2g"})
    assert validator.is_valid({"size": 2})
    assert not validator.is_valid({"size": 2.5})


def test_oneof_requires_exactly_one_match() -> None:
    schema = {"oneOf": [{"type": "string"}, {"type": "string", "minLength": 1}]}
    assert not SchemaValidator(schema).is_valid("x")  # matches both branches
    assert SchemaValidator(schema).is_valid("")  # matches only the first


def test_if_then_else() -> None:
    schema = {
        "type": "object",
        "if": {"properties": {"delivery": {"const": "file"}}, "required": ["delivery"]},
        "then": {"required": ["mode"]},
        "else": {"properties": {"mode": False}},
    }
    validator = SchemaValidator(schema)
    assert validator.is_valid({"delivery": "file", "mode": "0400"})
    assert not validator.is_valid({"delivery": "file"})
    assert validator.is_valid({"delivery": "env"})
    assert not validator.is_valid({"delivery": "env", "mode": "0400"})


def test_annotations_are_ignored() -> None:
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "urn:test",
        "title": "t",
        "description": "d",
        "$defs": {},
        "type": "object",
        "properties": {"a": {"type": "string", "default": "x", "$comment": "c"}},
    }
    assert SchemaValidator(schema).is_valid({"a": "b"})


def test_unsupported_keyword_is_a_definition_error() -> None:
    with pytest.raises(SchemaDefinitionError, match="unsupported schema keyword"):
        SchemaValidator({"type": "object", "dependentRequired": {}})


def test_dangling_ref_is_a_definition_error() -> None:
    with pytest.raises(SchemaDefinitionError, match="dangling"):
        SchemaValidator({"$ref": "#/$defs/missing"}).is_valid({})


def test_error_collection_is_capped() -> None:
    schema = {"type": "array", "items": {"type": "string"}}
    found = errors(schema, list(range(500)))
    assert len(found) <= 100
