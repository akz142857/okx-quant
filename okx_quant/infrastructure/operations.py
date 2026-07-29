"""心跳、告警 outbox 与可验证在线备份。"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import sqlite3
import subprocess
import threading
import time
import uuid
from collections.abc import Callable
from pathlib import Path

import requests

from okx_quant.infrastructure.db import JournalRepository


class HeartbeatService:
    def __init__(
        self,
        path: str | Path,
        interval_s: float = 5,
        health: Callable[[], bool] | None = None,
    ):
        self.path = Path(path)
        self.interval_s = interval_s
        self.health = health
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._stop.clear()
        self._systemd_notify("READY=1\nSTATUS=READY; reconciliation active")
        self._thread = threading.Thread(
            target=self._run, name="heartbeat", daemon=False
        )
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.is_set():
            healthy = self.health() if self.health is not None else True
            temporary = self.path.with_suffix(self.path.suffix + ".tmp")
            temporary.write_text(
                json.dumps({
                    "pid": os.getpid(),
                    "timestamp": time.time(),
                    "healthy": healthy,
                }),
                encoding="utf-8",
            )
            temporary.replace(self.path)
            if healthy:
                self._systemd_notify("WATCHDOG=1")
            self._stop.wait(self.interval_s)

    @staticmethod
    def _systemd_notify(message: str) -> None:
        address = os.environ.get("NOTIFY_SOCKET", "")
        if not address:
            return
        if address.startswith("@"):
            address = "\0" + address[1:]
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        try:
            sock.connect(address)
            sock.sendall(message.encode())
        finally:
            sock.close()

    def stop(self) -> None:
        self._systemd_notify("STOPPING=1")
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)


class AlertDispatcher:
    """交易进程内的低延迟发送器；独立 watchdog 是进程死亡兜底。"""

    def __init__(
        self,
        journal: JournalRepository,
        webhook_url: str = "",
        *,
        interval_s: float = 2,
    ):
        self.journal = journal
        self.webhook_url = webhook_url
        self.interval_s = interval_s
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.last_success_at = 0.0
        self.consecutive_failures = 0
        self.last_error = ""

    def start(self) -> None:
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, name="alert-outbox", daemon=False
        )
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.wait(self.interval_s):
            if not self.webhook_url:
                continue
            for event in self.journal.get_due_alerts():
                started_at = time.time()
                http_status = None
                try:
                    payload = json.loads(event["payload_json"])
                    response = requests.post(
                        self.webhook_url,
                        json={
                            "event_name": event["event_name"],
                            "event_id": event["event_id"],
                            "payload": payload,
                        },
                        timeout=5,
                    )
                    http_status = response.status_code
                    response.raise_for_status()
                    self.journal.record_alert_attempt(
                        event["event_id"],
                        started_at=started_at,
                        completed_at=time.time(),
                        http_status=http_status,
                        ingestion_accepted=True,
                    )
                    self.last_success_at = time.time()
                    self.consecutive_failures = 0
                    self.last_error = ""
                except Exception as exc:
                    self.journal.record_alert_attempt(
                        event["event_id"],
                        started_at=started_at,
                        completed_at=time.time(),
                        http_status=http_status,
                        ingestion_accepted=False,
                        error=f"{type(exc).__name__}: {exc}",
                    )
                    self.consecutive_failures += 1
                    self.last_error = str(exc)
                    continue

    def verify_delivery(self, payload: dict) -> None:
        """恢复交易前同步发送 challenge；没有 HTTP 成功 ACK 就 fail closed。"""
        if not self.webhook_url:
            raise RuntimeError("未配置告警 webhook，无法验证 Page 投递链")
        event_id = uuid.uuid4().hex
        try:
            response = requests.post(
                self.webhook_url,
                json={
                    "event_name": "resume_delivery_challenge",
                    "event_id": event_id,
                    "payload": payload,
                },
                timeout=5,
            )
            response.raise_for_status()
        except Exception as exc:
            self.consecutive_failures += 1
            self.last_error = str(exc)
            raise RuntimeError("恢复前 Page challenge 未获得成功 ACK") from exc
        self.last_success_at = time.time()
        self.consecutive_failures = 0
        self.last_error = ""
        self.journal.record_event(
            "resume_delivery_challenge_acknowledged",
            severity="critical",
            correlation_id=event_id,
            payload=payload,
        )

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)


class ResourceSampler:
    """Persist Linux process/cgroup/resource facts with explicit thresholds."""

    def __init__(
        self,
        journal: JournalRepository,
        *,
        database_path: str | Path,
        interval_s: float,
        memory_high_bytes: int,
        memory_max_bytes: int,
        limit_nofile: int,
        tasks_max: int,
        max_database_bytes: int,
        max_wal_bytes: int,
        max_wal_checkpoint_age_s: int,
        max_database_growth_bytes_per_day: int,
        min_free_bytes: int,
        min_free_inodes: int,
        release_identity: str,
        config_identity: str,
        proc_root: str | Path = "/proc",
        cgroup_root: str | Path = "/sys/fs/cgroup",
        metric_sink: Callable[[str, float], None] | None = None,
    ):
        self.journal = journal
        self.database_path = Path(database_path)
        self.interval_s = interval_s
        self.memory_high_bytes = memory_high_bytes
        self.memory_max_bytes = memory_max_bytes
        self.limit_nofile = limit_nofile
        self.tasks_max = tasks_max
        self.max_database_bytes = max_database_bytes
        self.max_wal_bytes = max_wal_bytes
        self.max_wal_checkpoint_age_s = max_wal_checkpoint_age_s
        self.max_database_growth_bytes_per_day = (
            max_database_growth_bytes_per_day
        )
        self.min_free_bytes = min_free_bytes
        self.min_free_inodes = min_free_inodes
        self.release_identity = release_identity
        self.config_identity = config_identity
        self.proc_root = Path(proc_root)
        self.cgroup_root = Path(cgroup_root)
        self.metric_sink = metric_sink
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._active_breaches: set[str] = set()
        self._last_oom_kill_count: int | None = None
        self._last_wal_checkpoint_at = 0.0

    @staticmethod
    def _key_values(path: Path) -> dict[str, int]:
        if not path.is_file():
            return {}
        result = {}
        for line in path.read_text(encoding="ascii").splitlines():
            key, separator, value = line.partition(" ")
            if separator and value.isdigit():
                result[key] = int(value)
        return result

    def _cgroup_path(self) -> Path | None:
        path = self.proc_root / "self/cgroup"
        if not path.is_file():
            return None
        for line in path.read_text(encoding="ascii").splitlines():
            hierarchy, controllers, relative = line.split(":", 2)
            if hierarchy == "0" and not controllers:
                candidate = (
                    self.cgroup_root / relative.lstrip("/")
                ).resolve()
                root = self.cgroup_root.resolve()
                if candidate == root or root in candidate.parents:
                    return candidate
        return None

    def sample_once(self) -> dict:
        status = {}
        for line in (self.proc_root / "self/status").read_text(
            encoding="ascii"
        ).splitlines():
            key, separator, value = line.partition(":")
            if separator:
                status[key] = value.strip()
        rss_kib = int(status.get("VmRSS", "0 kB").split()[0])
        threads = int(status.get("Threads", "0"))
        fd_count = len(list((self.proc_root / "self/fd").iterdir()))
        boot_id = (
            self.proc_root / "sys/kernel/random/boot_id"
        ).read_text(encoding="ascii").strip()
        cgroup = self._cgroup_path()
        memory_events = (
            self._key_values(cgroup / "memory.events") if cgroup else {}
        )
        cpu = self._key_values(cgroup / "cpu.stat") if cgroup else {}
        pids_current = (
            int((cgroup / "pids.current").read_text().strip())
            if cgroup and (cgroup / "pids.current").is_file()
            else threads
        )
        checkpoint = self.journal.passive_wal_checkpoint()
        checkpoint_completed_at = float(checkpoint["completed_at"])
        if checkpoint["busy"] == 0 and checkpoint["backlog_frames"] == 0:
            self._last_wal_checkpoint_at = checkpoint_completed_at
        checkpoint_age = (
            max(time.time() - self._last_wal_checkpoint_at, 0)
            if self._last_wal_checkpoint_at
            else float(self.max_wal_checkpoint_age_s + self.interval_s)
        )
        db_bytes = self.database_path.stat().st_size
        wal = self.database_path.with_name(self.database_path.name + "-wal")
        wal_bytes = wal.stat().st_size if wal.is_file() else 0
        usage = shutil.disk_usage(self.database_path.parent)
        filesystem = os.statvfs(self.database_path.parent)
        payload = {
            "boot_id": boot_id,
            "pid": os.getpid(),
            "release_identity": self.release_identity,
            "config_identity": self.config_identity,
            "rss_bytes": rss_kib * 1024,
            "fd_count": fd_count,
            "threads": threads,
            "pids_current": pids_current,
            "db_bytes": db_bytes,
            "wal_bytes": wal_bytes,
            "disk_free_bytes": usage.free,
            "disk_free_inodes": filesystem.f_favail,
            "memory_high_bytes": self.memory_high_bytes,
            "memory_max_bytes": self.memory_max_bytes,
            "limit_nofile": self.limit_nofile,
            "tasks_max": self.tasks_max,
            "max_database_bytes": self.max_database_bytes,
            "max_wal_bytes": self.max_wal_bytes,
            "wal_checkpoint_age_seconds": checkpoint_age,
            "max_wal_checkpoint_age_seconds": (
                self.max_wal_checkpoint_age_s
            ),
            "wal_checkpoint_busy": int(checkpoint["busy"] != 0),
            "wal_checkpoint_log_frames": checkpoint["log_frames"],
            "wal_checkpointed_frames": checkpoint["checkpointed_frames"],
            "wal_checkpoint_backlog_frames": checkpoint["backlog_frames"],
            "wal_checkpoint_page_size_bytes": checkpoint["page_size_bytes"],
            "wal_checkpoint_backlog_bytes": checkpoint["backlog_bytes"],
            "max_database_growth_bytes_per_day": (
                self.max_database_growth_bytes_per_day
            ),
            "min_free_bytes": self.min_free_bytes,
            "min_free_inodes": self.min_free_inodes,
            "oom_count": memory_events.get("oom", 0),
            "oom_kill_count": memory_events.get("oom_kill", 0),
            "cpu_nr_throttled": cpu.get("nr_throttled", 0),
            "cpu_throttled_usec": cpu.get("throttled_usec", 0),
        }
        breaches: set[str] = set()
        warnings: set[str] = set()
        if payload["rss_bytes"] >= self.memory_high_bytes * 0.85:
            breaches.add("RSS_85_PERCENT_MEMORY_HIGH")
        elif payload["rss_bytes"] >= self.memory_high_bytes * 0.70:
            warnings.add("RSS_70_PERCENT_MEMORY_HIGH")
        if fd_count >= self.limit_nofile * 0.80:
            breaches.add("FD_80_PERCENT_LIMIT")
        elif fd_count >= self.limit_nofile * 0.60:
            warnings.add("FD_60_PERCENT_LIMIT")
        if pids_current >= self.tasks_max:
            breaches.add("TASKS_MAX")
        if db_bytes >= self.max_database_bytes:
            breaches.add("DATABASE_ABSOLUTE_LIMIT")
        if wal_bytes >= self.max_wal_bytes:
            breaches.add("WAL_ABSOLUTE_LIMIT")
        if checkpoint_age >= self.max_wal_checkpoint_age_s:
            breaches.add("WAL_CHECKPOINT_AGE")
        elif checkpoint_age >= self.max_wal_checkpoint_age_s * 0.80:
            warnings.add("WAL_CHECKPOINT_AGE_80_PERCENT")
        if (
            self._last_oom_kill_count is not None
            and payload["oom_kill_count"] > self._last_oom_kill_count
        ):
            breaches.add("CGROUP_OOM_KILL")
        self._last_oom_kill_count = payload["oom_kill_count"]
        if usage.free < self.min_free_bytes:
            breaches.add("DISK_FREE_BYTES")
        if filesystem.f_favail < self.min_free_inodes:
            breaches.add("DISK_FREE_INODES")
        payload["warning_codes"] = sorted(warnings)
        payload["breach_codes"] = sorted(breaches)
        if self.metric_sink is not None:
            for metric_name, field in {
                "process_resident_memory_bytes": "rss_bytes",
                "process_open_fds": "fd_count",
                "process_threads": "threads",
                "cgroup_pids_current": "pids_current",
                "database_bytes": "db_bytes",
                "database_wal_bytes": "wal_bytes",
                "database_volume_free_bytes": "disk_free_bytes",
                "database_volume_free_inodes": "disk_free_inodes",
                "cgroup_oom_kill_count": "oom_kill_count",
                "cgroup_cpu_nr_throttled": "cpu_nr_throttled",
                "cgroup_cpu_throttled_seconds": "cpu_throttled_usec",
                "resource_memory_high_bytes": "memory_high_bytes",
                "resource_memory_max_bytes": "memory_max_bytes",
                "resource_limit_nofile": "limit_nofile",
                "resource_tasks_max": "tasks_max",
                "resource_database_max_bytes": "max_database_bytes",
                "resource_wal_max_bytes": "max_wal_bytes",
                "wal_checkpoint_age_seconds": (
                    "wal_checkpoint_age_seconds"
                ),
                "resource_wal_checkpoint_max_age_seconds": (
                    "max_wal_checkpoint_age_seconds"
                ),
                "wal_checkpoint_busy": "wal_checkpoint_busy",
                "wal_checkpoint_log_frames": (
                    "wal_checkpoint_log_frames"
                ),
                "wal_checkpointed_frames": "wal_checkpointed_frames",
                "wal_checkpoint_backlog_frames": (
                    "wal_checkpoint_backlog_frames"
                ),
                "wal_checkpoint_backlog_bytes": (
                    "wal_checkpoint_backlog_bytes"
                ),
            }.items():
                value = float(payload[field])
                if field == "cpu_throttled_usec":
                    value /= 1_000_000
                self.metric_sink(metric_name, value)
            self.metric_sink("resource_warning", float(bool(warnings)))
            self.metric_sink("resource_hard_breach", float(bool(breaches)))
        self.journal.record_event(
            "process_resource_sample",
            severity="critical" if breaches else "warning" if warnings else "info",
            payload=payload,
        )
        newly_active = (breaches | warnings) - self._active_breaches
        for code in sorted(newly_active):
            self.journal.enqueue_outbox(
                "page.resource_threshold"
                if code in breaches
                else "warning.resource_threshold",
                {
                    "code": code,
                    "boot_id": boot_id,
                    "pid": os.getpid(),
                    "release_identity": self.release_identity,
                    "config_identity": self.config_identity,
                },
            )
        self._active_breaches = breaches | warnings
        return payload

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.sample_once()
            except Exception as exc:  # noqa: BLE001
                self.journal.enqueue_outbox(
                    "page.resource_sampler_failed",
                    {"error": f"{type(exc).__name__}: {exc}"},
                )
            self._stop.wait(self.interval_s)

    def start(self) -> None:
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run,
            name="resource-sampler",
            daemon=False,
        )
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)


class BackupService:
    """SQLite online backup、恢复校验、保留与可选异地上传。"""

    def __init__(
        self,
        journal: JournalRepository,
        backup_dir: str | Path,
        *,
        interval_s: float = 300,
        retention_days: int = 30,
        offsite_uri: str = "",
        passphrase_env: str = "OKX_QUANT_BACKUP_PASSPHRASE",
    ):
        self.journal = journal
        self.backup_dir = Path(backup_dir)
        self.interval_s = interval_s
        self.retention_days = retention_days
        self.offsite_uri = offsite_uri
        self.passphrase_env = passphrase_env
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, name="online-backup", daemon=False
        )
        self._thread.start()

    def backup_once(self) -> Path:
        timestamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        destination = self.backup_dir / f"trading-{timestamp}.db"
        try:
            temporary = destination.with_name(
                f".{destination.name}.{uuid.uuid4().hex}.tmp"
            )
            self.journal.backup(temporary)
            probe = sqlite3.connect(
                f"file:{temporary}?mode=ro",
                uri=True,
            )
            try:
                row = probe.execute("PRAGMA integrity_check").fetchone()
                if not row or row[0] != "ok":
                    raise RuntimeError("备份恢复 integrity_check 失败")
            finally:
                probe.close()
            os.replace(temporary, destination)
        except Exception:
            if "temporary" in locals():
                temporary.unlink(missing_ok=True)
            self.journal.enqueue_outbox(
                "page.online_backup_failed",
                {"destination": str(destination)},
            )
            raise
        if self.offsite_uri:
            self._upload(destination)
        self.journal.record_event(
            "online_backup_verified",
            payload={
                "destination": str(destination),
                "offsite_uri": self.offsite_uri,
            },
        )
        self._prune()
        return destination

    def _upload(self, source: Path) -> None:
        if self.offsite_uri.startswith("s3://"):
            if not shutil.which("aws"):
                raise RuntimeError("配置了 S3 异地备份但找不到 aws CLI")
            if not os.environ.get(self.passphrase_env):
                raise RuntimeError(
                    f"异地备份缺少加密口令环境变量: {self.passphrase_env}"
                )
            encrypted = source.with_suffix(source.suffix + ".enc")
            checksum = encrypted.with_suffix(encrypted.suffix + ".sha256")
            subprocess.run(
                [
                    "openssl",
                    "enc",
                    "-aes-256-cbc",
                    "-salt",
                    "-pbkdf2",
                    "-in",
                    str(source),
                    "-out",
                    str(encrypted),
                    "-pass",
                    f"env:{self.passphrase_env}",
                ],
                check=True,
                timeout=120,
            )
            checksum.write_text(
                hashlib.sha256(encrypted.read_bytes()).hexdigest()
                + f"  {encrypted.name}\n",
                encoding="ascii",
            )
            destination = self.offsite_uri.rstrip("/") + "/"
            try:
                subprocess.run(
                    ["aws", "s3", "cp", str(encrypted), destination],
                    check=True,
                    timeout=120,
                )
                subprocess.run(
                    ["aws", "s3", "cp", str(checksum), destination],
                    check=True,
                    timeout=120,
                )
            finally:
                encrypted.unlink(missing_ok=True)
                checksum.unlink(missing_ok=True)
            return
        raise ValueError("offsite_backup_uri 当前仅支持 s3://")

    def _prune(self) -> None:
        """保留 24h 全量、2–7 天每小时一份、其后每天一份。"""
        now = time.time()
        cutoff = now - self.retention_days * 86400
        paths = sorted(
            self.backup_dir.glob("trading-*.db"),
            key=lambda item: item.stat().st_mtime,
            reverse=True,
        )
        retained_buckets: set[tuple[str, int]] = set()
        for path in paths:
            modified = path.stat().st_mtime
            age = now - modified
            if modified < cutoff:
                path.unlink()
                continue
            if age <= 86400:
                continue
            period = time.gmtime(modified)
            if age <= 7 * 86400:
                bucket = ("hour", int(time.strftime("%Y%m%d%H", period)))
            else:
                bucket = ("day", int(time.strftime("%Y%m%d", period)))
            if bucket in retained_buckets:
                path.unlink()
            else:
                retained_buckets.add(bucket)

    def _run(self) -> None:
        while not self._stop.wait(self.interval_s):
            try:
                self.backup_once()
            except Exception as exc:
                self.journal.enqueue_outbox(
                    "page.backup_failed", {"error": str(exc)}
                )

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=10)
