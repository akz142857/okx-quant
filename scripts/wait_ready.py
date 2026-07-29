#!/usr/bin/env python3
"""Wait for a local runtime /readyz endpoint without shell expansion."""

from __future__ import annotations

import argparse
import json
import time
import urllib.error
import urllib.request


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--timeout", type=float, default=60)
    args = parser.parse_args()
    if not args.url.startswith(("http://127.0.0.1:", "http://[::1]:")):
        raise ValueError("readyz URL 必须使用 loopback HTTP")
    deadline = time.monotonic() + args.timeout
    last_error = ""
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(args.url, timeout=2) as response:
                payload = json.loads(response.read())
                if response.status == 200 and payload.get("ready") is True:
                    return 0
                last_error = f"HTTP {response.status}: {payload}"
        except (OSError, ValueError, urllib.error.URLError) as exc:
            last_error = str(exc)
        time.sleep(0.5)
    raise TimeoutError(f"runtime 未在 {args.timeout}s ready: {last_error}")


if __name__ == "__main__":
    raise SystemExit(main())
