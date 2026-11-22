"""Profile validation: schema conformance plus semantic rules."""

from __future__ import annotations

import copy
import tomllib
from typing import Any

import pytest

from agentjail.errors import ValidationFailed
from agentjail.profile import (
    normalise_profile_document,
    validate_profile_document,
)
from tests.conftest import ALLOWLIST_PROFILE, FAKE_DIGEST, MINIMAL_PROFILE


def parse(text: str) -> dict[str, Any]:
    return tomllib.loads(text)


def valid_minimal() -> dict[str, Any]:
    return copy.deepcopy(parse(MINIMAL_PROFILE))


def valid_allowlist() -> dict[str, Any]:
    return copy.deepcopy(parse(ALLOWLIST_PROFILE))


def errors_of(document: dict[str, Any]) -> list[str]:
    with pytest.raises(ValidationFailed) as excinfo:
        validate_profile_document(document)
    return excinfo.value.errors


def assert_invalid(document: dict[str, Any], *fragments: str) -> list[str]:
    found = errors_of(document)
    text = "\n".join(found)
    for fragment in fragments:
        assert fragment in text, f"{fragment!r} not found in:\n{text}"
    return found


# --------------------------------------------------------------------------
# Valid documents
# --------------------------------------------------------------------------


def test_minimal_profile_is_valid() -> None:
    validate_profile_document(valid_minimal())


def test_allowlist_profile_is_valid() -> None:
    validate_profile_document(valid_allowlist())


def test_toml_roundtrip_of_example_shapes() -> None:
    assert parse(MINIMAL_PROFILE)["network"]["mode"] == "none"
    assert parse(ALLOWLIST_PROFILE)["network"]["egress"][0]["host"] == "api.example.com"


# --------------------------------------------------------------------------
# Secrets must be references
# --------------------------------------------------------------------------


@pytest.mark.parametrize("key", ["value", "inline", "literal", "plaintext", "content", "data"])
def test_inline_secret_value_is_rejected(key: str) -> None:
    document = valid_minimal()
    document["secrets"] = [
        {
            "name": "forge",
            "source": "env",
            "ref": "EXAMPLE_TOKEN",
            "target": "EXAMPLE_TOKEN",
            key: "fake-not-a-real-secret",
        }
    ]
    found = assert_invalid(document, "inline secret material is not allowed", key)
    assert any("secrets[0]" in error for error in found)


def test_secret_reference_shapes_are_accepted() -> None:
    document = valid_allowlist()
    document["secrets"] = [
        {"source": "env", "ref": "EXAMPLE_TOKEN", "target": "EXAMPLE_TOKEN"},
        {
            "source": "file",
            "ref": "/run/secrets/example",
            "delivery": "file",
            "target": "/tmp/agentjail/example",
        },
        {"source": "store", "ref": "default/example-token", "target": "EXAMPLE_STORE_TOKEN"},
    ]
    validate_profile_document(document)


def test_env_secret_delivery_rejects_mode() -> None:
    document = valid_minimal()
    document["secrets"] = [
        {"source": "env", "ref": "EXAMPLE_TOKEN", "target": "EXAMPLE_TOKEN", "mode": "0400"}
    ]
    assert_invalid(document, "mode")


def test_env_secret_ref_must_be_an_env_var_name() -> None:
    document = valid_minimal()
    document["secrets"] = [{"source": "env", "ref": "not a var", "target": "EXAMPLE_TOKEN"}]
    assert_invalid(document, "not a valid environment variable name")


def test_file_secret_ref_must_be_absolute() -> None:
    document = valid_minimal()
    document["secrets"] = [{"source": "file", "ref": "../secrets/x", "target": "X"}]
    assert_invalid(document, "must be an absolute path")


def test_file_secret_ref_rejects_fuse_path() -> None:
    document = valid_minimal()
    document["secrets"] = [
        {"source": "file", "ref": "/tmp/.mount_ab12cd/x", "delivery": "file", "target": "/tmp/x"}
    ]
    assert_invalid(document, "FUSE-backed")


def test_file_delivery_target_must_be_inside_tmpfs() -> None:
    document = valid_minimal()
    document["resources"] = {"tmpfs": {"/tmp": "64m"}}
    document["secrets"] = [
        {"source": "file", "ref": "/srv/secret", "delivery": "file", "target": "/work/secret"}
    ]
    assert_invalid(document, "not inside a declared tmpfs")


def test_file_delivery_target_inside_tmpfs_is_accepted() -> None:
    document = valid_minimal()
    document["resources"] = {"tmpfs": {"/tmp": "64m"}}
    document["secrets"] = [
        {"source": "file", "ref": "/srv/secret", "delivery": "file", "target": "/tmp/secrets/x"}
    ]
    validate_profile_document(document)


def test_duplicate_secret_targets_are_rejected() -> None:
    document = valid_minimal()
    document["secrets"] = [
        {"source": "env", "ref": "A_TOKEN", "target": "SAME"},
        {"source": "env", "ref": "B_TOKEN", "target": "SAME"},
    ]
    assert_invalid(document, "already used by secrets[0]")


# --------------------------------------------------------------------------
# Environment
# --------------------------------------------------------------------------


def test_secretish_env_name_is_rejected() -> None:
    document = valid_minimal()
    document["env"] = {"GITHUB_TOKEN": "value-in-profile"}
    assert_invalid(document, "names that look like credentials are rejected")


def test_long_tokenish_env_value_is_rejected() -> None:
    document = valid_minimal()
    document["env"] = {"SOMETHING": "a1" * 20}
    assert_invalid(document, "looks like a credential")


def test_ordinary_env_values_are_accepted() -> None:
    document = valid_minimal()
    document["env"] = {
        "LANG": "C.UTF-8",
        "TERM": "xterm-256color",
        "TZ": "UTC",
        "SHELL": "/bin/bash",
        "MAX_JOBS": 4,
        "COLOR": True,
    }
    validate_profile_document(document)


# --------------------------------------------------------------------------
# Mounts
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "source",
    [
        "/tmp/.mount_1a2b3c/bin/agent",
        "/run/user/1000/gvfs/smb-share/x",
        "/run/user/1000/doc/abc/file",
        "/home/me/Downloads/Agent-1.0.AppImage",
    ],
)
def test_fuse_and_appimage_mount_sources_are_rejected(source: str) -> None:
    document = valid_minimal()
    document["mounts"] = [{"source": source, "target": "/work/tool"}]
    found = assert_invalid(document, "FUSE-backed", "cannot be bind-mounted")
    assert "images/base/Containerfile" in "\n".join(found)


def test_normal_mount_source_is_accepted() -> None:
    document = valid_minimal()
    document["mounts"] = [{"source": "/srv/src/project", "target": "/work/project"}]
    validate_profile_document(document)


def test_duplicate_mount_targets_are_rejected() -> None:
    document = valid_minimal()
    document["mounts"] = [
        {"source": "/srv/a", "target": "/work/project"},
        {"source": "/srv/b", "target": "/work/project"},
    ]
    assert_invalid(document, "already mounted by mounts[0]")


@pytest.mark.parametrize("target", ["/", "/proc", "/sys", "/dev", "/run"])
def test_runtime_targets_cannot_be_overmounted(target: str) -> None:
    document = valid_minimal()
    document["mounts"] = [{"source": "/srv/a", "target": target}]
    assert_invalid(document, "refusing to mount over")


def test_mounting_the_jail_home_is_rejected() -> None:
    document = valid_minimal()
    document["mounts"] = [{"source": "/srv/a", "target": "/home/agent"}]
    assert_invalid(document, "is the jail home")


# --------------------------------------------------------------------------
# Network
# --------------------------------------------------------------------------


def test_dns_is_required() -> None:
    document = copy.deepcopy(valid_minimal())
    del document["network"]["dns"]
    assert_invalid(document, "missing required property 'dns'")


def test_no_egress_is_not_allowable_in_mode_none() -> None:
    document = valid_minimal()
    document["network"]["egress"] = [{"host": "api.example.com", "port": 443}]
    assert_invalid(document, "at most 0 item(s)")


def test_allowlist_requires_a_destination() -> None:
    document = copy.deepcopy(valid_allowlist())
    document["network"]["egress"] = []
    assert_invalid(document, "needs at least 1 item(s)")


def test_allowlist_mode_requires_gateway_or_pinned_dns() -> None:
    document = copy.deepcopy(valid_allowlist())
    document["network"]["dns"] = "none"
    assert_invalid(document, "must be one of")


def test_wildcard_egress_is_rejected() -> None:
    document = copy.deepcopy(valid_allowlist())
    document["network"]["egress"][0]["host"] = "*.example.com"
    assert_invalid(document, "wildcard")


def test_egress_with_scheme_or_port_is_rejected() -> None:
    document = copy.deepcopy(valid_allowlist())
    document["network"]["egress"][0]["host"] = "https://api.example.com"
    assert_invalid(document, "bare DNS name")


def test_duplicate_egress_is_rejected() -> None:
    document = copy.deepcopy(valid_allowlist())
    document["network"]["egress"].append({"host": "api.example.com", "port": 443})
    assert_invalid(document, "duplicate of network.egress[0]")


def test_raw_tcp_egress_is_limited_to_443() -> None:
    document = copy.deepcopy(valid_allowlist())
    document["network"]["egress"] = [{"host": "api.example.com", "port": 22, "protocol": "tcp"}]
    assert_invalid(document, "raw tcp egress")


def test_unknown_protocol_is_rejected() -> None:
    document = copy.deepcopy(valid_allowlist())
    document["network"]["egress"][0]["protocol"] = "udp"
    assert_invalid(document, "must be one of")


# --------------------------------------------------------------------------
# Image, paths, agent, resources
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "digest",
    ["sha256:abc", "sha256:" + "Z" * 64, "md5:" + "0" * 32, ""],
)
def test_image_digest_must_be_a_sha256_pin(digest: str) -> None:
    document = valid_minimal()
    document["image"]["digest"] = digest
    assert_invalid(document, "digest")


def test_image_name_must_be_fully_qualified() -> None:
    document = valid_minimal()
    document["image"]["name"] = "agentjail-base:1"
    assert_invalid(document, "image.name")


def test_digest_is_required_not_just_a_tag() -> None:
    document = valid_minimal()
    del document["image"]["digest"]
    assert_invalid(document, "missing required property 'digest'")


def test_workdir_must_not_be_root() -> None:
    document = valid_minimal()
    document["workdir"] = "/"
    assert_invalid(document, "must not be the jail root")


def test_workdir_and_home_must_differ() -> None:
    document = valid_minimal()
    document["home"] = "/work"
    assert_invalid(document, "workdir and home must differ")


def test_agent_relative_path_is_rejected() -> None:
    document = valid_minimal()
    document["agent"]["command"] = "bin/agent"
    assert_invalid(document, "relative path")


def test_agent_unknown_placeholder_is_rejected() -> None:
    document = valid_minimal()
    document["agent"]["args"] = ["--dir", "{home}", "{token}"]
    assert_invalid(document, "unknown placeholder {token}")


def test_agent_known_placeholders_are_accepted() -> None:
    document = valid_minimal()
    document["agent"]["args"] = ["--dir", "{workdir}", "--home", "{home}"]
    validate_profile_document(document)


def test_resources_size_patterns() -> None:
    document = valid_minimal()
    document["resources"] = {"memory": "two gigs", "disk": "4G", "nofile": 1}
    assert_invalid(document, "resources.memory", "resources.nofile")


def test_tmpfs_keys_must_be_absolute() -> None:
    document = valid_minimal()
    document["resources"] = {"tmpfs": {"tmp": "64m"}}
    assert_invalid(document, "not an absolute in-jail path")


def test_unknown_top_level_key_is_rejected() -> None:
    document = valid_minimal()
    document["orca_session"] = "abc"
    assert_invalid(document, "unknown property")


def test_unknown_network_key_is_rejected() -> None:
    document = valid_minimal()
    document["network"]["proxy"] = "http://example"
    assert_invalid(document, "unknown property")


def test_multiple_errors_are_collected() -> None:
    document = valid_minimal()
    document["workdir"] = "/"
    document["env"] = {"API_KEY": "x"}
    document["image"]["digest"] = "sha256:short"
    found = errors_of(document)
    assert len(found) >= 3
    assert any("digest" in error for error in found)
    assert any("workdir" in error for error in found)
    assert any("API_KEY" in error for error in found)


# --------------------------------------------------------------------------
# Normalisation
# --------------------------------------------------------------------------


def test_defaults_are_materialised() -> None:
    document = normalise_profile_document(parse(ALLOWLIST_PROFILE))
    assert document["mounts"][0]["read_only"] is True
    assert document["mounts"][0]["required"] is True
    assert document["network"]["egress"][0]["protocol"] == "tls"
    assert document["secrets"][0]["delivery"] == "env"
    assert "mode" not in document["secrets"][0]
    assert document["resources"]["cpus"] == 2
    assert document["resources"]["nofile"] == 1024
    assert document["resources"]["tmpfs"] == {"/tmp": "64m"}
    assert document["agent"]["args"] == ["-lc", "true"]


def test_file_secret_defaults_to_0400() -> None:
    document = valid_minimal()
    document["resources"] = {"tmpfs": {"/tmp": "64m"}}
    document["secrets"] = [
        {"source": "file", "ref": "/srv/secret", "delivery": "file", "target": "/tmp/secret"}
    ]
    normalised = normalise_profile_document(document)
    assert normalised["secrets"][0]["mode"] == "0400"
    assert normalised["secrets"][0]["name"] == "/tmp/secret"


def test_env_values_are_stringified() -> None:
    document = valid_minimal()
    document["env"] = {"JOBS": 4, "COLOR": False}
    normalised = normalise_profile_document(document)
    assert normalised["env"] == {"JOBS": "4", "COLOR": "false"}


def test_normalisation_does_not_mutate_input() -> None:
    original = valid_allowlist()
    snapshot = copy.deepcopy(original)
    normalise_profile_document(original)
    assert original == snapshot


def test_fixture_digest_is_obviously_fake() -> None:
    assert FAKE_DIGEST == "sha256:" + "0" * 64
