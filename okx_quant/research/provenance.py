"""Self-contained, signed-evidence-ready dataset provenance artifacts."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from io import StringIO
from urllib.parse import urlparse

import pandas as pd

from okx_quant.backtest.validation import validate_ohlcv
from okx_quant.research.costs import (
    canonical_manifest_hash,
    dataframe_manifest,
)


def canonical_artifact_bytes(artifact: dict) -> bytes:
    return json.dumps(
        artifact,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def normalize_dataset(data: pd.DataFrame, *, context: str) -> pd.DataFrame:
    if "ts" not in data.columns:
        raise ValueError(f"{context} 缺少 ts")
    normalized = data.copy()
    normalized["ts"] = pd.to_datetime(
        normalized["ts"],
        utc=True,
        errors="raise",
    )
    normalized = (
        normalized.sort_values("ts")
        .drop_duplicates("ts", keep="last")
        .reset_index(drop=True)
    )
    validate_ohlcv(normalized, context=context)
    return normalized


def build_dataset_provenance(
    datasets: dict[str, pd.DataFrame],
    *,
    kind: str,
    provider: str,
    bar: str,
    source_uri: str,
    source_version_id: str,
    retrieved_at: datetime,
) -> dict:
    """Build embedded source bytes whose hashes Gate can independently replay."""
    if kind not in {"walk_forward", "portfolio"}:
        raise ValueError("dataset kind 必须是 walk_forward/portfolio")
    if kind == "walk_forward" and len(datasets) != 1:
        raise ValueError("walk_forward provenance 必须精确包含一个交易对")
    if not datasets:
        raise ValueError("dataset provenance 至少需要一个数据集")
    if not provider.strip() or not bar.strip():
        raise ValueError("provider/bar 不能为空")
    source = urlparse(source_uri)
    if (
        source.scheme != "s3"
        or not source.netloc
        or not source.path.strip("/")
        or not source_version_id.strip()
    ):
        raise ValueError("source 必须绑定 S3 URI 和不可变 version id")
    if retrieved_at.tzinfo is None or retrieved_at.utcoffset() is None:
        raise ValueError("retrieved_at 必须包含时区")
    normalized = {
        inst_id: normalize_dataset(data, context=f"{kind}:{inst_id}")
        for inst_id, data in sorted(datasets.items())
    }
    artifact = {
        "version": 1,
        "kind": kind,
        "provider": provider,
        "bar": bar,
        "datasets": {
            inst_id: dataframe_manifest(data)
            for inst_id, data in normalized.items()
        },
    }
    component_hashes = {
        inst_id: canonical_manifest_hash(payload)
        for inst_id, payload in artifact["datasets"].items()
    }
    dataset_hash = (
        next(iter(component_hashes.values()))
        if kind == "walk_forward"
        else canonical_manifest_hash(component_hashes)
    )
    all_timestamps = pd.concat(
        [data["ts"] for data in normalized.values()],
        ignore_index=True,
    )
    return {
        "version": 2,
        "kind": kind,
        "provider": provider,
        "source_uri": source_uri,
        "source_version_id": source_version_id,
        "source_sha256": hashlib.sha256(
            canonical_artifact_bytes(artifact)
        ).hexdigest(),
        "source_artifact": artifact,
        "dataset_hash": dataset_hash,
        "retrieved_at": retrieved_at.astimezone(UTC).isoformat(),
        "start_at": all_timestamps.min().isoformat(),
        "end_at": all_timestamps.max().isoformat(),
        "instruments": sorted(normalized),
        "bar": bar,
        "rows": sum(len(data) for data in normalized.values()),
    }


def frames_from_artifact(artifact: object) -> dict[str, pd.DataFrame]:
    if (
        not isinstance(artifact, dict)
        or set(artifact)
        != {"version", "kind", "provider", "bar", "datasets"}
        or artifact["version"] != 1
        or artifact["kind"] not in {"walk_forward", "portfolio"}
        or not isinstance(artifact["datasets"], dict)
        or not artifact["datasets"]
    ):
        raise ValueError("dataset source_artifact 结构非法")
    frames: dict[str, pd.DataFrame] = {}
    for inst_id, payload in sorted(artifact["datasets"].items()):
        if (
            not isinstance(inst_id, str)
            or not inst_id
            or not isinstance(payload, dict)
            or set(payload) != {"columns", "dtypes", "data"}
            or not isinstance(payload["columns"], list)
            or not isinstance(payload["dtypes"], list)
            or len(payload["columns"]) != len(payload["dtypes"])
        ):
            raise ValueError("dataset source_artifact dataframe manifest 非法")
        try:
            split = json.loads(payload["data"])
            if set(split) != {"columns", "index", "data"}:
                raise ValueError("split keys")
            if split["columns"] != payload["columns"]:
                raise ValueError("columns mismatch")
            frame = pd.read_json(
                StringIO(payload["data"]),
                orient="split",
            )
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ValueError("dataset source_artifact data 非法") from exc
        if "ts" not in frame:
            raise ValueError("dataset source_artifact 缺少 ts")
        frame["ts"] = pd.to_datetime(frame["ts"], utc=True, errors="raise")
        if (
            not frame["ts"].is_monotonic_increasing
            or frame["ts"].duplicated().any()
        ):
            raise ValueError("dataset source_artifact 时间必须严格递增且唯一")
        frame = frame.reset_index(drop=True)
        validate_ohlcv(frame, context=f"source_artifact:{inst_id}")
        frames[inst_id] = frame
    return frames
