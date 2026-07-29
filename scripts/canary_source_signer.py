#!/usr/bin/env python3
"""Sign one Canary source after exact-byte parsing and identity checks."""

from __future__ import annotations

import argparse
from pathlib import Path

from okx_quant.ops.canary_producer import sign_source


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--context", required=True, type=Path)
    parser.add_argument("--collection-receipt", required=True, type=Path)
    parser.add_argument("--iam-sts-receipt", required=True, type=Path)
    parser.add_argument("--iam-output", required=True, type=Path)
    parser.add_argument("--private-key", required=True, type=Path)
    parser.add_argument(
        "--collector-executable",
        required=True,
        type=Path,
    )
    parser.add_argument("--signer-executable", required=True, type=Path)
    parser.add_argument("--parser", required=True, type=Path)
    parser.add_argument("--host-image-sha256", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    sign_source(
        inventory_path=args.inventory,
        context_path=args.context,
        collection_receipt_path=args.collection_receipt,
        iam_sts_receipt_path=args.iam_sts_receipt,
        iam_receipt_output_path=args.iam_output,
        private_key_path=args.private_key,
        collector_executable_path=args.collector_executable,
        signer_executable_path=args.signer_executable,
        parser_path=args.parser,
        host_image_sha256_path=args.host_image_sha256,
        output_path=args.output,
    )
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
