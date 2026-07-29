"""Frozen candidate identity shared by Stage-C drills and the soak epoch."""

from __future__ import annotations

import hashlib
import re

from okx_quant.application.approval import canonical_bytes

_SHA256 = re.compile(r"[0-9a-f]{64}")
_ROOT_KEYS = {
    "version",
    "exact_release",
    "instrumented",
    "host_image_sha256",
    "network_namespace_sha256",
    "cgroup_policy_sha256",
    "observer_api_key_fingerprint",
    "source_key_fingerprints",
    "safety_behavior_sha256",
    "build_provenance_sha256",
}
_CLASS_KEYS = {
    "account_uid",
    "config_sha256",
    "unit",
    "artifact_sha256",
}


def validate_stage_c_chaos_deployment_identity(value: object) -> dict:
    if not isinstance(value, dict) or set(value) != _ROOT_KEYS:
        raise ValueError("Stage-C candidate deployment identity schema 非法")
    if value["version"] != 1:
        raise ValueError("Stage-C candidate deployment identity version 非法")
    for artifact_class in ("exact_release", "instrumented"):
        identity = value[artifact_class]
        if (
            not isinstance(identity, dict)
            or set(identity) != _CLASS_KEYS
            or not str(identity["account_uid"]).strip()
            or not str(identity["unit"]).startswith("okx-quant-")
            or not _SHA256.fullmatch(str(identity["config_sha256"]))
            or not _SHA256.fullmatch(str(identity["artifact_sha256"]))
        ):
            raise ValueError(
                f"Stage-C {artifact_class} candidate identity 非法"
            )
    fingerprints = value["source_key_fingerprints"]
    scalar_hashes = (
        "host_image_sha256",
        "network_namespace_sha256",
        "cgroup_policy_sha256",
        "observer_api_key_fingerprint",
        "safety_behavior_sha256",
        "build_provenance_sha256",
    )
    if (
        any(not _SHA256.fullmatch(str(value[key])) for key in scalar_hashes)
        or not isinstance(fingerprints, list)
        or len(fingerprints) < 3
        or fingerprints != sorted(fingerprints)
        or len(set(fingerprints)) != len(fingerprints)
        or any(not _SHA256.fullmatch(str(item)) for item in fingerprints)
        or value["observer_api_key_fingerprint"] in fingerprints
        or value["exact_release"] == value["instrumented"]
    ):
        raise ValueError("Stage-C candidate host/network/key/safety identity 非法")
    return value


def stage_c_chaos_deployment_identity_sha256(value: object) -> str:
    identity = validate_stage_c_chaos_deployment_identity(value)
    return hashlib.sha256(canonical_bytes(identity)).hexdigest()
