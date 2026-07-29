#!/usr/bin/env python3
"""Publish or independently verify a signed Object-Lock JSON evidence bundle."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import math
import os
import sys
import tempfile
import uuid
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from okx_quant.application.approval import verify_ed25519_artifact
from okx_quant.infrastructure.evidence import ed25519_public_key_fingerprint
from okx_quant.infrastructure.immutable_bundle import (
    build_bundle_manifest,
    build_bundle_receipt,
    put_locked_object,
    scan_json_evidence,
    sign_bundle_manifest,
    sign_independent_bundle_verification,
    validate_external_daily_verification,
    verify_bundle_artifact,
    verify_locked_object,
)
from okx_quant.ops.backup_receipt import validate_restore_evidence
from okx_quant.ops.slo_facts import (
    export_slo_v2_facts,
    verify_daily_slo_components,
)


def _timestamp(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise argparse.ArgumentTypeError("timestamp 必须带时区")
    return parsed.astimezone(UTC)


def _component(value: str) -> tuple[str, Path]:
    name, separator, raw_path = value.partition("=")
    if not separator or not name or not raw_path:
        raise argparse.ArgumentTypeError("component 必须是 name=/path/file.json")
    return name, Path(raw_path)


def _external_key(value: str) -> tuple[str, Path]:
    name, separator, raw_path = value.partition("=")
    if (
        not separator
        or name
        not in {
            "journal_snapshot",
            "external_monitor",
            "alert_receipts",
            "backup_receipts",
        }
        or not raw_path
    ):
        raise argparse.ArgumentTypeError(
            "external signing key 必须是受支持的 name=/path/public.pem"
        )
    return name, Path(raw_path)


def _alert_role_key(value: str) -> tuple[str, Path]:
    name, separator, raw_path = value.partition("=")
    if (
        not separator
        or name not in {"provider", "human-ack", "escalation"}
        or not raw_path
    ):
        raise argparse.ArgumentTypeError(
            "alert role key 必须是 provider|human-ack|"
            "escalation=/path/public.pem"
        )
    return name, Path(raw_path)


def _base() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    publish = subparsers.add_parser("publish")
    publish.add_argument(
        "--kind",
        required=True,
        choices=("daily", "chaos", "restart"),
    )
    publish.add_argument("--identity", required=True, type=Path)
    publish.add_argument(
        "--component",
        required=True,
        action="append",
        type=_component,
    )
    publish.add_argument("--s3-prefix", required=True)
    publish.add_argument("--retain-until", required=True, type=_timestamp)
    publish.add_argument("--kms-key-id", required=True)
    publish.add_argument("--private-key", required=True, type=Path)
    publish.add_argument("--signing-key-id", required=True)
    publish.add_argument("--secret-env", action="append", default=[])
    publish.add_argument("--manifest-output", required=True, type=Path)
    publish.add_argument("--receipt-output", required=True, type=Path)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--manifest", required=True, type=Path)
    verify.add_argument("--manifest-uri", required=True)
    verify.add_argument("--manifest-version-id", required=True)
    verify.add_argument("--identity", required=True, type=Path)
    verify.add_argument("--public-key", required=True, type=Path)
    verify.add_argument("--minimum-retain-until", required=True, type=_timestamp)
    verify.add_argument("--kms-key-id", required=True)
    verify.add_argument(
        "--verifier-private-key",
        required=True,
        type=Path,
    )
    verify.add_argument("--verifier-key-id", required=True)
    verify.add_argument(
        "--external-verification-summary",
        required=True,
        type=Path,
        help=(
            "独立 verifier 对 journal snapshot、external monitor、"
            "alert/backup 原始签名 artifacts 的 exact-version 复验摘要"
        ),
    )
    verify.add_argument(
        "--external-signing-public-key",
        required=True,
        action="append",
        type=_external_key,
        help=(
            "四类 exact-version 日聚合 artifact 的 Ed25519 公钥；"
            "逐项使用 name=/path/public.pem"
        ),
    )
    verify.add_argument(
        "--alert-receipt-public-key",
        required=True,
        action="append",
        type=_alert_role_key,
        help=(
            "provider/human-ack/escalation 三种原始 receipt 的独立公钥"
        ),
    )
    verify.add_argument("--receipt-output", required=True, type=Path)
    return parser


def _s3_join(prefix: str, *parts: str) -> str:
    if not prefix.startswith("s3://"):
        raise ValueError("--s3-prefix 必须使用 s3://")
    return prefix.rstrip("/") + "/" + "/".join(part.strip("/") for part in parts)


def _exclusive_output(path: Path, value: object) -> None:
    if path.exists() or path.is_symlink():
        raise RuntimeError(f"拒绝覆盖既有输出: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False)
        + "\n",
        encoding="utf-8",
    )
    path.chmod(0o600)


def _publish(args: argparse.Namespace) -> dict:
    if args.manifest_output.exists() or args.receipt_output.exists():
        raise RuntimeError("manifest/receipt 输出已存在")
    identity = json.loads(args.identity.read_text(encoding="utf-8"))
    bundle_id = uuid.uuid4().hex
    secrets = tuple(os.environ.get(name, "") for name in args.secret_env)
    components: dict[str, tuple[bytes, str, str]] = {}
    for name, path in args.component:
        if name in components:
            raise RuntimeError(f"component 名称重复: {name}")
        payload = path.read_bytes()
        scan_json_evidence(payload, forbidden_values=secrets)
        uri = _s3_join(args.s3_prefix, bundle_id, f"{name}.json")
        version_id = put_locked_object(
            source=path,
            object_uri=uri,
            retain_until=args.retain_until,
            kms_key_id=args.kms_key_id,
        )
        components[name] = (payload, uri, version_id)
    manifest = build_bundle_manifest(
        bundle_id=bundle_id,
        kind=args.kind,
        identity=identity,
        components=components,
        retain_until=args.retain_until,
        signing_key_id=args.signing_key_id,
        created_at=datetime.now(UTC),
    )
    artifact = sign_bundle_manifest(manifest, args.private_key)
    _exclusive_output(args.manifest_output, artifact)
    manifest_bytes = args.manifest_output.read_bytes()
    manifest_uri = _s3_join(args.s3_prefix, bundle_id, "manifest.json")
    manifest_version = put_locked_object(
        source=args.manifest_output,
        object_uri=manifest_uri,
        retain_until=args.retain_until,
        kms_key_id=args.kms_key_id,
    )
    verify_locked_object(
        object_uri=manifest_uri,
        version_id=manifest_version,
        expected_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        expected_bytes=len(manifest_bytes),
        minimum_retain_until=args.retain_until,
        expected_kms_key_id=args.kms_key_id,
    )
    receipt = build_bundle_receipt(
        manifest_uri=manifest_uri,
        manifest_version_id=manifest_version,
        manifest_bytes=manifest_bytes,
        verified_at=datetime.now(UTC),
    )
    _exclusive_output(args.receipt_output, receipt)
    return receipt


def _decoded_source_artifacts(claims: dict) -> list[tuple[bytes, dict, str]]:
    decoded = []
    for item in claims["artifacts"]:
        if (
            not isinstance(item, dict)
            or set(item) != {"sha256", "bytes_base64"}
            or not isinstance(item["bytes_base64"], str)
        ):
            raise RuntimeError("external source artifact wrapper 非法")
        try:
            payload = base64.b64decode(
                item["bytes_base64"],
                validate=True,
            )
            artifact = json.loads(payload)
        except (binascii.Error, ValueError, json.JSONDecodeError) as exc:
            raise RuntimeError(
                "external source artifact bytes/base64/JSON 非法"
            ) from exc
        digest = hashlib.sha256(payload).hexdigest()
        if digest != item["sha256"]:
            raise RuntimeError("external source inner artifact hash 不匹配")
        decoded.append((payload, artifact, digest))
    return decoded


def _verify_journal_snapshot(
    decoded: list[tuple[bytes, dict, str]],
    *,
    public_key: Path,
    day: str,
    identity: dict,
    expected_facts: dict,
    minimum_retain_until: datetime,
    kms_key_id: str,
) -> None:
    if len(decoded) != 1:
        raise RuntimeError("journal snapshot locator 必须精确为一个")
    locator = verify_ed25519_artifact(
        decoded[0][1],
        public_key,
        label="exact journal snapshot locator",
    )
    if (
        not isinstance(locator, dict)
        or set(locator)
        != {
            "version",
            "action",
            "day",
            "account_id",
            "object_uri",
            "version_id",
            "sha256",
            "bytes",
        }
        or locator["version"] != 1
        or locator["action"] != "attest-exact-journal-snapshot"
        or locator["day"] != day
        or locator["account_id"] != identity["account_uid"]
    ):
        raise RuntimeError("journal snapshot locator identity 非法")
    snapshot = verify_locked_object(
        object_uri=locator["object_uri"],
        version_id=locator["version_id"],
        expected_sha256=locator["sha256"],
        expected_bytes=locator["bytes"],
        minimum_retain_until=minimum_retain_until,
        expected_kms_key_id=kms_key_id,
    )
    with tempfile.NamedTemporaryFile(suffix=".db") as handle:
        handle.write(snapshot)
        handle.flush()
        rebuilt = export_slo_v2_facts(
            Path(handle.name),
            date.fromisoformat(day),
        )
    if rebuilt != expected_facts:
        raise RuntimeError(
            "exact journal snapshot 重建 facts 与 daily bundle 不一致"
        )


def _verify_monitor_artifacts(
    decoded: list[tuple[bytes, dict, str]],
    *,
    public_key: Path,
    day: str,
    identity: dict,
) -> None:
    signal_max_age_seconds = {
        "host": 120,
        "service": 60,
        "provider": 900,
        "evidence-close": 90_000,
        "backup": 300,
    }
    signal_claim_keys = {
        "status",
        "latency_seconds",
        "ok",
        "signal",
        "observed_at",
        "age_seconds",
        "maximum_age_seconds",
        "deadman_id",
        "target",
        "release_identity",
        "config_identity",
        "account_uid",
        "deployment_unit",
        "soak_epoch_id",
    }

    def finite_number(value: object) -> bool:
        return (
            not isinstance(value, bool)
            and isinstance(value, (int, float))
            and math.isfinite(float(value))
        )

    started = datetime.fromisoformat(f"{day}T00:00:00+00:00")
    ended = started + timedelta(days=1)
    observed: list[datetime] = []
    for _payload, artifact, _digest in decoded:
        claims = verify_ed25519_artifact(
            artifact,
            public_key,
            label="external monitor observation",
        )
        expected_target = str(identity["unit"])
        expected_target = expected_target.removeprefix(
            "okx-quant-"
        ).removesuffix(".service")
        expected_claim_keys = {
            "version",
            "action",
            "target",
            "event_id",
            "signing_key_id",
            "expected_release",
            "expected_config",
            "expected_account_uid",
            "expected_unit",
            "soak_epoch_id",
            "started_at",
            "completed_at",
            "endpoints",
            "signals",
            "clock",
            "failures",
            "deliveries",
            "ok",
        }
        if (
            not isinstance(claims, dict)
            or set(claims) != expected_claim_keys
            or claims.get("version") != 1
            or claims.get("action") != "attest-external-demo-synthetic"
            or claims.get("expected_release") != identity["git_commit"]
            or claims.get("expected_config") != identity["config_sha256"]
            or claims.get("expected_account_uid")
            != identity["account_uid"]
            or claims.get("expected_unit") != identity["unit"]
            or claims.get("soak_epoch_id") != identity["soak_epoch_id"]
            or claims.get("target") != expected_target
            or not str(claims.get("signing_key_id", "")).strip()
            or claims.get("ok") is not True
            or claims.get("failures") != []
            or claims.get("deliveries") != []
        ):
            raise RuntimeError("external monitor observation 语义非法")
        endpoints = claims["endpoints"]
        signals = claims["signals"]
        clock = claims["clock"]
        if (
            not isinstance(endpoints, dict)
            or set(endpoints) != {"health", "ready"}
            or any(
                not isinstance(endpoints[name], dict)
                or set(endpoints[name])
                != {
                    "status",
                    "latency_seconds",
                    "live",
                    "ready",
                    "release_identity",
                    "config_identity",
                    "account_uid",
                    "deployment_unit",
                    "soak_epoch_id",
                }
                or endpoints[name]["status"] != 200
                or not math.isfinite(
                    float(endpoints[name]["latency_seconds"])
                )
                or float(endpoints[name]["latency_seconds"]) < 0
                or endpoints[name]["release_identity"]
                != identity["git_commit"]
                or endpoints[name]["config_identity"]
                != identity["config_sha256"]
                or endpoints[name]["account_uid"]
                != identity["account_uid"]
                or endpoints[name]["deployment_unit"]
                != identity["unit"]
                or endpoints[name]["soak_epoch_id"]
                != identity["soak_epoch_id"]
                for name in ("health", "ready")
            )
            or endpoints["health"]["live"] is not True
            or endpoints["ready"]["ready"] is not True
            or not isinstance(signals, dict)
            or set(signals) != set(signal_max_age_seconds)
            or any(
                not isinstance(signals[name], dict)
                or set(signals[name]) != signal_claim_keys
                or signals[name]["status"] != 200
                or not finite_number(signals[name]["latency_seconds"])
                or float(signals[name]["latency_seconds"]) < 0
                or signals[name]["ok"] is not True
                or signals[name]["signal"] != name
                or not finite_number(signals[name]["observed_at"])
                or not finite_number(signals[name]["age_seconds"])
                or float(signals[name]["age_seconds"]) < -5
                or float(signals[name]["age_seconds"])
                > signal_max_age_seconds[name]
                or signals[name]["maximum_age_seconds"]
                != signal_max_age_seconds[name]
                or not isinstance(signals[name]["deadman_id"], str)
                or not signals[name]["deadman_id"].strip()
                or signals[name]["target"] != expected_target
                or signals[name]["release_identity"]
                != identity["git_commit"]
                or signals[name]["config_identity"]
                != identity["config_sha256"]
                or signals[name]["account_uid"]
                != identity["account_uid"]
                or signals[name]["deployment_unit"] != identity["unit"]
                or signals[name]["soak_epoch_id"]
                != identity["soak_epoch_id"]
                for name in signal_max_age_seconds
            )
            or len({
                signals[name]["deadman_id"]
                for name in signal_max_age_seconds
            }) != len(signal_max_age_seconds)
            or not isinstance(clock, dict)
            or set(clock)
            != {
                "status",
                "latency_seconds",
                "midpoint_offset_seconds",
            }
            or clock["status"] != 200
            or not math.isfinite(float(clock["latency_seconds"]))
            or float(clock["latency_seconds"]) < 0
            or not math.isfinite(float(clock["midpoint_offset_seconds"]))
            or abs(float(clock["midpoint_offset_seconds"])) > 1
        ):
            raise RuntimeError("external monitor endpoint/clock 事实非法")
        event_id = hashlib.sha256(
            json.dumps(
                {
                    "target": claims["target"],
                    "release": claims["expected_release"],
                    "config": claims["expected_config"],
                    "account_uid": claims["expected_account_uid"],
                    "unit": claims["expected_unit"],
                    "soak_epoch_id": claims["soak_epoch_id"],
                    "failures": [],
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        if claims["event_id"] != event_id:
            raise RuntimeError("external monitor event identity 非法")
        started_at = datetime.fromtimestamp(
            float(claims["started_at"]),
            tz=UTC,
        )
        completed = datetime.fromtimestamp(
            float(claims["completed_at"]),
            tz=UTC,
        )
        if (
            not started <= started_at <= completed < ended
            or completed - started_at > timedelta(seconds=30)
            or any(
                abs(
                    started_at.timestamp()
                    - float(signals[name]["observed_at"])
                    - float(signals[name]["age_seconds"])
                )
                > 0.01
                for name in signal_max_age_seconds
            )
        ):
            raise RuntimeError("external monitor observation 日期非法")
        observed.append(completed)
    observed.sort()
    if (
        not observed
        or observed[0] - started > timedelta(minutes=5)
        or ended - observed[-1] > timedelta(minutes=5)
        or any(
            right - left > timedelta(minutes=5)
            for left, right in zip(observed, observed[1:], strict=False)
        )
    ):
        raise RuntimeError("external monitor observation 覆盖存在 >5m gap")


def _alert_artifact_hashes(facts: dict) -> set[str]:
    return {
        str(row[key])
        for row in facts["tables"]["alerts"]
        for key in (
            "provider_artifact_sha256",
            "human_ack_artifact_sha256",
        )
        if str(row.get(key) or "").strip()
    }


def _verify_alert_artifacts(
    decoded: list[tuple[bytes, dict, str]],
    *,
    public_keys: dict[str, Path],
    facts: dict,
) -> None:
    if set(public_keys) != {"provider", "human-ack", "escalation"}:
        raise RuntimeError("alert role public keys 配置不完整")
    digests = set()
    for _payload, artifact, digest in decoded:
        unsigned = artifact.get("payload") if isinstance(artifact, dict) else {}
        action = unsigned.get("action") if isinstance(unsigned, dict) else ""
        role = {
            "confirm-alert-provider-received": "provider",
            "confirm-alert-human-ack": "human-ack",
            "confirm-alert-escalation": "escalation",
        }.get(action)
        if role is None:
            raise RuntimeError("alert receipt action 非法")
        claims = verify_ed25519_artifact(
            artifact,
            public_keys[role],
            label="alert provider/human receipt",
        )
        if (
            action
            not in {
                "confirm-alert-provider-received",
                "confirm-alert-human-ack",
                "confirm-alert-escalation",
            }
            or claims.get("version") != 1
            or not str(claims.get("event_id", "")).strip()
            or type(claims.get("issued_at")) is not int
        ):
            raise RuntimeError("alert receipt schema/identity 非法")
        digests.add(digest)
    if digests != _alert_artifact_hashes(facts):
        raise RuntimeError("alert receipt 集合与 frozen SLO facts 不一致")


def _backup_artifact_hashes(facts: dict) -> set[str]:
    result = set()
    for row in facts["tables"]["system_events"]:
        if row["event_name"] != "backup_slo_sample":
            continue
        payload = json.loads(row["payload_json"])
        digest = str(payload.get("evidence_artifact_sha256", ""))
        if digest:
            result.add(digest)
    return result


def _verify_backup_artifacts(
    decoded: list[tuple[bytes, dict, str]],
    *,
    public_key: Path,
    facts: dict,
    account_id: str,
    minimum_retain_until: datetime,
    kms_key_id: str,
) -> None:
    digests = set()
    for _payload, artifact, digest in decoded:
        claims = verify_ed25519_artifact(
            artifact,
            public_key,
            label="offsite backup receipt",
        )
        if not isinstance(claims, dict):
            raise RuntimeError("offsite backup receipt 非法")
        validate_restore_evidence(
            claims,
            expected_account_id=account_id,
            expected_key_id=str(claims.get("evidence_key_id", "")),
            now=float(claims.get("roundtrip_completed_at", 0)),
        )
        verify_locked_object(
            object_uri=claims["archive_uri"],
            version_id=claims["archive_version_id"],
            expected_sha256=claims["archive_sha256"],
            expected_bytes=claims["archive_bytes"],
            minimum_retain_until=minimum_retain_until,
            expected_kms_key_id=kms_key_id,
        )
        verify_locked_object(
            object_uri=claims["manifest_uri"],
            version_id=claims["manifest_version_id"],
            expected_sha256=claims["manifest_sha256"],
            expected_bytes=claims["manifest_bytes"],
            minimum_retain_until=minimum_retain_until,
            expected_kms_key_id=kms_key_id,
        )
        digests.add(digest)
    if digests != _backup_artifact_hashes(facts):
        raise RuntimeError("backup receipt 集合与 frozen SLO facts 不一致")


def _verify(args: argparse.Namespace) -> dict:
    if args.receipt_output.exists():
        raise RuntimeError("receipt 输出已存在")
    manifest_bytes = args.manifest.read_bytes()
    remote_manifest = verify_locked_object(
        object_uri=args.manifest_uri,
        version_id=args.manifest_version_id,
        expected_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        expected_bytes=len(manifest_bytes),
        minimum_retain_until=args.minimum_retain_until,
        expected_kms_key_id=args.kms_key_id,
    )
    artifact = json.loads(remote_manifest)
    identity = json.loads(args.identity.read_text(encoding="utf-8"))
    components = verify_bundle_artifact(
        artifact,
        public_key=args.public_key,
        expected_identity=identity,
        minimum_retain_until=args.minimum_retain_until,
        expected_kms_key_id=args.kms_key_id,
    )
    manifest = artifact["payload"]
    if manifest["kind"] != "daily":
        raise RuntimeError(
            "独立 verifier 当前只签署可重算的 daily bundle"
        )
    recomputation = verify_daily_slo_components(
        components,
        identity=identity,
    )
    external_verification = validate_external_daily_verification(
        json.loads(
            args.external_verification_summary.read_text(
                encoding="utf-8"
            )
        )
    )
    if external_verification["day"] != recomputation["day"]:
        raise RuntimeError("外部原始事实复验摘要与 daily bundle 日期不一致")
    external_keys = dict(args.external_signing_public_key)
    alert_role_keys = dict(args.alert_receipt_public_key)
    expected_external_names = {
        "journal_snapshot",
        "external_monitor",
        "alert_receipts",
        "backup_receipts",
    }
    if (
        len(external_keys) != len(args.external_signing_public_key)
        or set(external_keys) != expected_external_names
        or len(alert_role_keys) != len(args.alert_receipt_public_key)
        or set(alert_role_keys)
        != {"provider", "human-ack", "escalation"}
    ):
        raise RuntimeError(
            "四类 external signing 和三类 alert role 公钥必须各提供一次"
        )
    external_fingerprints = {
        name: ed25519_public_key_fingerprint(path)
        for name, path in external_keys.items()
    }
    reserved_fingerprints = {
        ed25519_public_key_fingerprint(args.public_key),
        ed25519_public_key_fingerprint(
            args.verifier_private_key,
            private_key=True,
        ),
    }
    alert_role_fingerprints = {
        name: ed25519_public_key_fingerprint(path)
        for name, path in alert_role_keys.items()
    }
    if (
        len(set(external_fingerprints.values()))
        != len(expected_external_names)
        or set(external_fingerprints.values()) & reserved_fingerprints
        or len(set(alert_role_fingerprints.values())) != 3
        or set(alert_role_fingerprints.values())
        & (
            reserved_fingerprints
            | set(external_fingerprints.values())
        )
    ):
        raise RuntimeError(
            "四类 external source、三类 alert role、bundle publisher 与 verifier "
            "必须使用互不相同的 Ed25519 key"
        )
    expected_facts = json.loads(components["slo-facts-v2"])
    for name in (
        "journal_snapshot",
        "external_monitor",
        "alert_receipts",
        "backup_receipts",
    ):
        component = external_verification[name]
        payload = verify_locked_object(
            object_uri=component["object_uri"],
            version_id=component["version_id"],
            expected_sha256=component["sha256"],
            expected_bytes=component["bytes"],
            minimum_retain_until=args.minimum_retain_until,
            expected_kms_key_id=args.kms_key_id,
        )
        scan_json_evidence(payload)
        claims = verify_ed25519_artifact(
            json.loads(payload),
            external_keys[name],
            label=f"daily external source {name}",
        )
        if (
            not isinstance(claims, dict)
            or set(claims)
            != {
                "version",
                "action",
                "day",
                "source",
                "signing_key_id",
                "artifacts",
                "all_signatures_valid",
            }
            or claims["version"] != 1
            or claims["action"]
            != "attest-daily-external-source-artifacts"
            or claims["day"] != recomputation["day"]
            or claims["source"] != name
            or not str(claims["signing_key_id"]).strip()
            or not isinstance(claims["artifacts"], list)
            or len(claims["artifacts"]) != component["artifact_count"]
            or not claims["artifacts"]
            or claims["all_signatures_valid"] is not True
            or external_fingerprints[name]
            != component["signing_key_fingerprint"]
        ):
            raise RuntimeError(
                f"external source {name} 聚合签名/identity/count 非法"
            )
        decoded = _decoded_source_artifacts(claims)
        if name == "journal_snapshot":
            _verify_journal_snapshot(
                decoded,
                public_key=external_keys[name],
                day=recomputation["day"],
                identity=identity,
                expected_facts=expected_facts,
                minimum_retain_until=args.minimum_retain_until,
                kms_key_id=args.kms_key_id,
            )
        elif name == "external_monitor":
            _verify_monitor_artifacts(
                decoded,
                public_key=external_keys[name],
                day=recomputation["day"],
                identity=identity,
            )
        elif name == "alert_receipts":
            _verify_alert_artifacts(
                decoded,
                public_keys=alert_role_keys,
                facts=expected_facts,
            )
        else:
            _verify_backup_artifacts(
                decoded,
                public_key=external_keys[name],
                facts=expected_facts,
                account_id=identity["account_uid"],
                minimum_retain_until=args.minimum_retain_until,
                kms_key_id=args.kms_key_id,
            )
    recomputation["external_verification"] = external_verification
    receipt = sign_independent_bundle_verification(
        manifest=manifest,
        manifest_uri=args.manifest_uri,
        manifest_version_id=args.manifest_version_id,
        manifest_bytes=remote_manifest,
        recomputation=recomputation,
        manifest_signing_public_key=args.public_key,
        verifier_key_id=args.verifier_key_id,
        verifier_private_key=args.verifier_private_key,
        verified_at=datetime.now(UTC),
    )
    _exclusive_output(args.receipt_output, receipt)
    return receipt


def main() -> int:
    args = _base().parse_args()
    result = _publish(args) if args.command == "publish" else _verify(args)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
