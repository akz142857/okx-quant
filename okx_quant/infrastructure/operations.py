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
            for event in self.journal.get_unpublished_outbox():
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
                    response.raise_for_status()
                    self.journal.mark_outbox_published(event["event_id"])
                    self.last_success_at = time.time()
                    self.consecutive_failures = 0
                    self.last_error = ""
                except Exception as exc:
                    self.consecutive_failures += 1
                    self.last_error = str(exc)
                    break

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
