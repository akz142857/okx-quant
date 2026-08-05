"""LLM 请求 record/replay 缓存

用途：让同一份离线评估集可以**零成本重复跑**、可离线复现。第一次跑写盘
（record），之后同样的请求直接命中缓存（replay），不再发网络请求。

缓存 key 覆盖**所有影响输出的入参**：provider / model / base_url /
temperature / max_tokens / system / user。只用 ``system+user+model`` 做 key
是不够的——``LLMConfig.temperature`` 默认是 0.3（非 0），不同采样温度的结果
混同后，采样噪声会被误读成"改动带来的效应"。

边界（必须清楚，否则会把缓存当成它不是的东西）：
  * **缓存只降本，不消除非确定性。** temperature > 0 时缓存冻结的是"某一次
    采样"，不是期望表现。要测期望必须同一输入跑 N 次并报告分布——那与缓存
    的省钱目的直接冲突，需要显式取舍。
  * **prompt 一改就全 miss。** 任何 prompt/框架改动都会击穿缓存，而"改动前
    vs 改动后"恰恰是唯一有意义的对比场景。缓存能覆盖 baseline 侧与回归重跑，
    **变更侧必须真实付费**，做预算时不能把这笔钱算掉。
  * 失败响应（``LLMResponse.ok`` 为 False）**不落盘**，避免把一次网络抖动
    永久固化成"这个输入就是失败的"。

用法::

    cache = LLMCache("state/llm_cache")
    client = LLMCache.wrap(LLMClient(cfg), cache)
    client.chat(system, user)          # 首次真实调用并落盘，之后命中缓存
    print(cache.stats())
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import logging
import os
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .client import LLMClient, LLMConfig, LLMResponse

logger = logging.getLogger(__name__)

CacheMode = Literal["off", "rw", "replay"]

#: 参与 key 计算的 LLMConfig 字段。**不含 api_key**（同一份缓存应能跨密钥复用，
#: 且密钥绝不进磁盘）。新增任何会影响模型输出的字段时必须同步加进来。
_KEY_CONFIG_FIELDS = ("provider", "model", "base_url", "temperature", "max_tokens")

_CACHE_FORMAT_VERSION = 1


@dataclass
class LLMCacheStats:
    """缓存命中统计"""

    hits: int = 0
    misses: int = 0
    writes: int = 0
    skipped_errors: int = 0

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


class LLMCache:
    """LLM 请求的磁盘 record/replay 缓存

    Args:
        cache_dir: 缓存目录，不存在则创建
        mode: ``rw`` 命中即用、未命中则真实调用并落盘（默认）；
              ``replay`` 只读，未命中直接返回错误响应（**绝不发网络请求**，
              用于保证离线复现时不会偷偷产生新的真实调用）；
              ``off`` 完全旁路
    """

    def __init__(self, cache_dir: str | Path, mode: CacheMode = "rw"):
        if mode not in ("off", "rw", "replay"):
            raise ValueError(f"未知缓存模式: {mode}")
        self.mode = mode
        self.dir = Path(cache_dir)
        if mode != "off":
            self.dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._stats = LLMCacheStats()

    # ------------------------------------------------------------------
    # key
    # ------------------------------------------------------------------

    @staticmethod
    def make_key(config: LLMConfig, system: str, user: str) -> str:
        """按所有影响输出的入参计算稳定 key"""
        material = {
            "v": _CACHE_FORMAT_VERSION,
            **{f: getattr(config, f, None) for f in _KEY_CONFIG_FIELDS},
            "system": system,
            "user": user,
        }
        blob = json.dumps(material, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def _path_for(self, key: str) -> Path:
        # 两级分片，避免单目录几万个文件
        return self.dir / key[:2] / f"{key}.json"

    # ------------------------------------------------------------------
    # 读写
    # ------------------------------------------------------------------

    def get(self, config: LLMConfig, system: str, user: str) -> LLMResponse | None:
        """命中返回 LLMResponse，未命中返回 None"""
        if self.mode == "off":
            return None
        path = self._path_for(self.make_key(config, system, user))
        if not path.exists():
            with self._lock:
                self._stats.misses += 1
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            resp = LLMResponse(**payload["response"])
        except (OSError, ValueError, KeyError, TypeError) as e:
            logger.warning("[LLMCache] 缓存读取失败 %s: %s（按未命中处理）", path.name, e)
            with self._lock:
                self._stats.misses += 1
            return None
        with self._lock:
            self._stats.hits += 1
        return resp

    def put(self, config: LLMConfig, system: str, user: str, resp: LLMResponse) -> None:
        """落盘一次响应；失败响应不缓存"""
        if self.mode != "rw":
            return
        if not resp.ok:
            with self._lock:
                self._stats.skipped_errors += 1
            return

        key = self.make_key(config, system, user)
        path = self._path_for(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "key": key,
            # meta 只记录 key 材料里的非敏感字段，便于人工排查；绝不写 api_key
            "meta": {f: getattr(config, f, None) for f in _KEY_CONFIG_FIELDS},
            "response": dataclasses.asdict(resp),
        }
        blob = json.dumps(payload, ensure_ascii=False, indent=2)
        try:
            # 原子写：多线程/多进程并发跑评估集时避免读到半截文件
            fd, tmp = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    f.write(blob)
                os.replace(tmp, path)
            except BaseException:
                Path(tmp).unlink(missing_ok=True)
                raise
        except OSError as e:
            logger.warning("[LLMCache] 缓存写入失败 %s: %s", path.name, e)
            return
        with self._lock:
            self._stats.writes += 1

    # ------------------------------------------------------------------

    def stats(self) -> dict:
        with self._lock:
            return self._stats.to_dict()

    def log_stats(self, prefix: str = "[LLMCache]") -> None:
        s = self.stats()
        total = s["hits"] + s["misses"]
        rate = (s["hits"] / total * 100) if total else 0.0
        logger.info(
            "%s 命中 %d / 未命中 %d（命中率 %.1f%%），写入 %d，跳过失败响应 %d",
            prefix, s["hits"], s["misses"], rate, s["writes"], s["skipped_errors"],
        )

    # ------------------------------------------------------------------

    @staticmethod
    def wrap(client: LLMClient, cache: LLMCache | None) -> LLMClient:
        """把 LLMClient 包成带缓存的版本；cache 为 None 或 off 时原样返回"""
        if cache is None or cache.mode == "off":
            return client
        return CachedLLMClient(client, cache)  # type: ignore[return-value]


class CachedLLMClient:
    """LLMClient 的缓存代理

    只拦截 ``chat()``；``config`` 等属性透传，以便调用方（如
    ``MultiAgentStrategy.model_name``）拿到真实模型名。
    """

    def __init__(self, client: LLMClient, cache: LLMCache):
        self._client = client
        self._cache = cache

    @property
    def config(self) -> LLMConfig:
        return self._client.config

    @property
    def cache(self) -> LLMCache:
        return self._cache

    def chat(self, system: str, user: str) -> LLMResponse:
        cfg = self._client.config
        hit = self._cache.get(cfg, system, user)
        if hit is not None:
            return hit
        if self._cache.mode == "replay":
            # 严格复现模式：未命中绝不真实调用，否则"离线复现"会悄悄变成付费重跑
            return LLMResponse(error="LLM cache replay miss（严格复现模式下不发起真实调用）")
        resp = self._client.chat(system, user)
        self._cache.put(cfg, system, user, resp)
        return resp

    def __getattr__(self, item):
        return getattr(self._client, item)
