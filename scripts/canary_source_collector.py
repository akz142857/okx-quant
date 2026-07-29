#!/usr/bin/env python3
"""Collect one exact Canary native source under its isolated systemd user."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from okx_quant.ops.canary_producer import collect_source


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument("--collection-receipt", required=True, type=Path)
    args = parser.parse_args()
    receipt = collect_source(
        inventory_path=args.inventory,
        request_path=args.request,
        collection_receipt_path=args.collection_receipt,
    )
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
