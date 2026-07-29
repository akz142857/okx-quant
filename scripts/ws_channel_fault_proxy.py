#!/usr/bin/env python3
"""Channel-specific transparent TCP fault proxy for demo-chaos WebSockets."""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import os
import stat
import time
from pathlib import Path

CONNECT_TIMEOUT_S = 10.0
MAX_CONNECT_TIMEOUT_S = 30.0
CONTROL_POLL_SECONDS = 0.1


def read_control(path: Path, *, expected_owner_uid: int = 0) -> str:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError as exc:
        raise RuntimeError("fault proxy control 无法安全打开") from exc
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != expected_owner_uid
            or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or info.st_size > 16
        ):
            raise RuntimeError(
                "fault proxy control 必须由期望身份持有、不可被非 owner 写入"
            )
        with os.fdopen(os.dup(descriptor), "r", encoding="ascii") as handle:
            value = handle.read(17).strip()
    finally:
        os.close(descriptor)
    if value not in {"open", "blocked"}:
        raise RuntimeError("fault proxy control 只能是 open/blocked")
    return value


def emit(channel: str, event: str, **fields: object) -> None:
    print(
        json.dumps(
            {
                "timestamp": time.time(),
                "channel": channel,
                "event": event,
                **fields,
            },
            sort_keys=True,
        ),
        flush=True,
    )


async def _pipe(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    while payload := await reader.read(64 * 1024):
        writer.write(payload)
        await writer.drain()


async def _open_upstream(
    host: str,
    port: int,
    *,
    timeout: float,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    if not math.isfinite(timeout) or not 0.1 <= timeout <= MAX_CONNECT_TIMEOUT_S:
        raise ValueError("upstream connect timeout 必须位于 0.1..30 秒")
    try:
        return await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
    except TimeoutError as exc:
        raise TimeoutError(
            f"upstream connect 未在 {timeout}s 完成"
        ) from exc


async def _serve(args: argparse.Namespace) -> None:
    active: set[asyncio.StreamWriter] = set()

    async def connection(
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        active.add(client_writer)
        peer = str(client_writer.get_extra_info("peername"))
        if read_control(args.control) != "open":
            emit(args.channel, "connection_rejected_blocked", peer=peer)
            client_writer.close()
            await client_writer.wait_closed()
            active.discard(client_writer)
            return
        try:
            upstream_reader, upstream_writer = await _open_upstream(
                args.upstream_host,
                args.upstream_port,
                timeout=args.connect_timeout,
            )
        except Exception as exc:
            emit(args.channel, "upstream_connect_failed", error=str(exc))
            client_writer.close()
            await client_writer.wait_closed()
            active.discard(client_writer)
            return
        active.add(upstream_writer)
        emit(args.channel, "connection_opened", peer=peer)

        async def block_watch() -> None:
            while True:
                if read_control(args.control) != "open":
                    emit(args.channel, "connection_forced_closed", peer=peer)
                    return
                await asyncio.sleep(CONTROL_POLL_SECONDS)

        tasks = {
            asyncio.create_task(_pipe(client_reader, upstream_writer)),
            asyncio.create_task(_pipe(upstream_reader, client_writer)),
            asyncio.create_task(block_watch()),
        }
        try:
            _, pending = await asyncio.wait(
                tasks,
                return_when=asyncio.FIRST_COMPLETED,
            )
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
        finally:
            for writer in (client_writer, upstream_writer):
                active.discard(writer)
                writer.close()
                await writer.wait_closed()
            emit(args.channel, "connection_closed", peer=peer)

    server = await asyncio.start_server(
        connection,
        args.listen_host,
        args.listen_port,
    )
    emit(
        args.channel,
        "proxy_ready",
        pid=os.getpid(),
        listen=f"{args.listen_host}:{args.listen_port}",
        upstream=f"{args.upstream_host}:{args.upstream_port}",
    )
    async with server:
        await server.serve_forever()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--channel",
        required=True,
        choices=("public", "private", "business"),
    )
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", required=True, type=int)
    parser.add_argument("--upstream-host", default="wspap.okx.com")
    parser.add_argument("--upstream-port", default=8443, type=int)
    parser.add_argument(
        "--connect-timeout",
        default=CONNECT_TIMEOUT_S,
        type=float,
    )
    parser.add_argument("--control", required=True, type=Path)
    args = parser.parse_args()
    if args.listen_host not in {"127.0.0.1", "::1"}:
        raise ValueError("fault proxy 只允许监听 loopback")
    if not 1 <= args.listen_port <= 65535:
        raise ValueError("fault proxy listen port 非法")
    if (
        not math.isfinite(args.connect_timeout)
        or not 0.1 <= args.connect_timeout <= MAX_CONNECT_TIMEOUT_S
    ):
        raise ValueError("upstream connect timeout 必须位于 0.1..30 秒")
    read_control(args.control)
    try:
        asyncio.run(_serve(args))
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
