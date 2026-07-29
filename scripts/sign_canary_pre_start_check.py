#!/usr/bin/env python3
"""Sign an externally collected Canary pre-start source.

This compatibility entry point uses the same isolated signer implementation as
``canary_source_signer.py``.  It cannot accept operator-supplied facts.
"""

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
    artifact = sign_source(
        inventory_path=args.inventory,
        context_path=args.context,
        collection_receipt_path=args.collection_receipt,
        iam_sts_receipt_path=args.iam_sts_receipt,
        private_key_path=args.private_key,
        collector_executable_path=args.collector_executable,
        signer_executable_path=args.signer_executable,
        parser_path=args.parser,
        host_image_sha256_path=args.host_image_sha256,
        output_path=args.output,
    )
    if artifact["payload"]["check"] not in {
        "account_uid_verified",
        "api_key_read_trade_only",
        "api_key_withdraw_disabled",
        "ip_allowlist_verified",
        "journal_identity_verified",
        "limits_match_policy",
        "release_identity_verified",
    }:
        raise RuntimeError("context 不是 pre-start producer")
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
