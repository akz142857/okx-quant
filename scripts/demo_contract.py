#!/usr/bin/env python3
"""验证生产采用的独立 OCO 路线，并探测 attached TP/SL 路线。"""

from __future__ import annotations

import argparse
import json
import re
import time
import uuid
from decimal import ROUND_DOWN, ROUND_UP, Decimal
from pathlib import Path

import requests

from main import make_client
from okx_quant.config import load_yaml
from okx_quant.infrastructure.okx.contract_fixture import (
    build_redacted_contract_fixture,
)

CONFIRMATION = "I_UNDERSTAND_DEMO_TRADES"
# OKX 51000 是通用参数错误，不能证明 attached 能力不受支持。
# 只有未来经官方契约确认的专用能力码才可加入此集合。
ATTACHED_CONTRACT_REJECTION_CODES: frozenset[str] = frozenset()


def text(value: Decimal) -> str:
    return format(value.normalize(), "f")


def _price_on_tick(
    value: Decimal,
    tick: Decimal,
    *,
    rounding: str,
) -> Decimal:
    return (value / tick).to_integral_value(rounding=rounding) * tick


def _poll_order(
    client,
    inst_id: str,
    cl_ord_id: str,
    *,
    timeout_s: float,
    interval_s: float,
) -> dict:
    deadline = time.monotonic() + timeout_s
    order: dict = {}
    while time.monotonic() < deadline:
        order = client.get_order(inst_id, cl_ord_id=cl_ord_id)
        if order.get("state") in {"filled", "canceled"}:
            return order
        time.sleep(interval_s)
    return order


def _net_base_qty(order: dict, base_ccy: str, lot: Decimal) -> Decimal:
    filled = Decimal(str(order.get("accFillSz") or "0"))
    fee = Decimal(str(order.get("fee") or "0"))
    if str(order.get("feeCcy", "")).upper() == base_ccy.upper():
        filled += fee
    if filled <= 0:
        return Decimal("0")
    return (filled / lot).to_integral_value(rounding=ROUND_DOWN) * lot


def _find_algo(client, inst_id: str, algo_cl_ord_id: str) -> dict:
    try:
        found = client.get_algo_order(algo_cl_ord_id=algo_cl_ord_id)
        if found:
            return found
    except Exception:
        pass
    for kind in ("oco", "conditional"):
        for row in client.get_pending_algo_orders(
            inst_id=inst_id,
            ord_type=kind,
        ):
            if row.get("algoClOrdId") == algo_cl_ord_id:
                return row
    return {}


def _algo_is_active(
    algo: dict,
    *,
    inst_id: str,
    algo_cl_ord_id: str,
    expected_qty: Decimal,
    expected_stop: Decimal,
    expected_take: Decimal,
) -> bool:
    try:
        return bool(
            algo.get("algoId")
            and algo.get("algoClOrdId") == algo_cl_ord_id
            and str(algo.get("instId", inst_id)) == inst_id
            and str(algo.get("side", "")).lower() == "sell"
            and str(algo.get("ordType", "oco")).lower() == "oco"
            and str(algo.get("state", "")).lower() == "live"
            and Decimal(str(algo.get("sz"))) == expected_qty
            and Decimal(str(algo.get("slTriggerPx"))) == expected_stop
            and Decimal(str(algo.get("tpTriggerPx"))) == expected_take
        )
    except Exception:
        return False


def _poll_active_algo(
    client,
    *,
    inst_id: str,
    algo_cl_ord_id: str,
    expected_qty: Decimal,
    expected_stop: Decimal,
    expected_take: Decimal,
    timeout_s: float,
    interval_s: float,
) -> dict:
    deadline = time.monotonic() + timeout_s
    last: dict = {}
    while time.monotonic() < deadline:
        last = _find_algo(client, inst_id, algo_cl_ord_id)
        if _algo_is_active(
            last,
            inst_id=inst_id,
            algo_cl_ord_id=algo_cl_ord_id,
            expected_qty=expected_qty,
            expected_stop=expected_stop,
            expected_take=expected_take,
        ):
            return last
        time.sleep(interval_s)
    return last


def _poll_algo_inactive(
    client,
    *,
    inst_id: str,
    algo_cl_ord_id: str,
    timeout_s: float,
    interval_s: float,
) -> tuple[bool, dict]:
    deadline = time.monotonic() + timeout_s
    last: dict = {}
    while time.monotonic() < deadline:
        last = _find_algo(client, inst_id, algo_cl_ord_id)
        if not last or str(last.get("state", "")).lower() not in {
            "live",
            "new",
            "pause",
        }:
            return True, last
        time.sleep(interval_s)
    return False, last


def _base_balance(client, base_ccy: str) -> Decimal:
    rows = client.get_balance(base_ccy)
    for account in rows:
        for detail in account.get("details", []):
            if str(detail.get("ccy", "")).upper() == base_ccy.upper():
                return Decimal(str(detail.get("cashBal") or "0"))
    return Decimal("0")


def _attached_rejection_code(error: str) -> str:
    matched = re.search(r"OKX API Error \[(\d+)\]", error)
    return matched.group(1) if matched else ""


def _place_or_resolve_order(
    client,
    *,
    inst_id: str,
    cl_ord_id: str,
    size: Decimal,
    tgt_ccy: str,
    timeout_s: float,
    interval_s: float,
    attach_algo_orders: list[dict] | None = None,
) -> tuple[dict, str]:
    error = ""
    try:
        client.place_order(
            inst_id,
            "buy",
            "market",
            text(size),
            tgt_ccy=tgt_ccy,
            cl_ord_id=cl_ord_id,
            max_slippage="0.01",
            attach_algo_orders=attach_algo_orders,
        )
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        if isinstance(
            exc,
            (requests.ConnectionError, requests.Timeout),
        ):
            # 传输错误不能证明请求未到达，必须仍按 clOrdId 查询。
            pass
        elif "OKX API Error" in str(exc):
            return {}, error
    order = _poll_order(
        client,
        inst_id,
        cl_ord_id,
        timeout_s=timeout_s,
        interval_s=interval_s,
    )
    return order, error


def run_contract(
    client,
    inst_id: str,
    *,
    poll_timeout_s: float = 15,
    poll_interval_s: float = 0.5,
) -> tuple[dict, bool]:
    instrument = client.get_instrument(inst_id)
    ticker = client.get_ticker(inst_id)
    price = Decimal(str(ticker["last"]))
    lot = Decimal(str(instrument["lotSz"]))
    minimum = Decimal(str(instrument["minSz"]))
    tick = Decimal(str(instrument["tickSz"]))
    if price <= 0 or lot <= 0 or minimum <= 0 or tick <= 0:
        raise RuntimeError("产品精度或行情无效，拒绝执行 demo contract")
    base_ccy = str(instrument.get("baseCcy") or inst_id.split("-")[0])
    baseline_base_balance = _base_balance(client, base_ccy)
    quantity = max(minimum, lot)
    quantity = (quantity / lot).to_integral_value(rounding=ROUND_UP) * lot
    nonce = uuid.uuid4().hex[:12]
    independent_order_id = f"ib{nonce}"
    independent_algo_id = f"ia{nonce}"
    attached_order_id = f"ab{nonce}"
    attached_algo_id = f"aa{nonce}"
    cleanup_qty = Decimal("0")
    cleanup_algos: set[str] = set()
    cleanup_algo_cl_ids: dict[str, str] = {}
    cleanup: list[dict] = []
    cleanup_errors: list[str] = []
    evidence: dict = {
        "started_at": time.time(),
        "environment": "OKX demo",
        "inst_id": inst_id,
        "requested_base_qty": text(quantity),
        "selected_route": "independent_oco_after_fill",
        "cleanup": cleanup,
    }
    route_b_ok = False
    attached_probe_conclusive = False

    try:
        order, error = _place_or_resolve_order(
            client,
            inst_id=inst_id,
            cl_ord_id=independent_order_id,
            size=quantity,
            tgt_ccy="base_ccy",
            timeout_s=poll_timeout_s,
            interval_s=poll_interval_s,
        )
        net_qty = _net_base_qty(order, base_ccy, lot)
        if net_qty > 0:
            cleanup_qty += net_qty
        evidence["independent_parent"] = {
            "clOrdId": independent_order_id,
            "state": order.get("state"),
            "ordId": order.get("ordId"),
            "accFillSz": order.get("accFillSz"),
            "avgPx": order.get("avgPx"),
            "fee": order.get("fee"),
            "feeCcy": order.get("feeCcy"),
            "transport_error": error,
        }
        if order.get("state") != "filled" or net_qty <= 0:
            raise RuntimeError("独立 OCO 路线的父订单未确认完整成交")
        fill_price = Decimal(str(order.get("avgPx") or price))
        stop = _price_on_tick(
            fill_price * Decimal("0.98"),
            tick,
            rounding=ROUND_DOWN,
        )
        take = _price_on_tick(
            fill_price * Decimal("1.02"),
            tick,
            rounding=ROUND_UP,
        )
        placed_algo: dict = {}
        algo_error = ""
        try:
            placed_algo = client.place_algo_order(
                inst_id=inst_id,
                side="sell",
                ord_type="oco",
                sz=text(net_qty),
                algo_cl_ord_id=independent_algo_id,
                stop_loss=text(stop),
                take_profit=text(take),
            )
        except Exception as exc:
            algo_error = f"{type(exc).__name__}: {exc}"
        if placed_algo.get("algoId"):
            placed_id = str(placed_algo["algoId"])
            cleanup_algos.add(placed_id)
            cleanup_algo_cl_ids[placed_id] = independent_algo_id
        algo = _poll_active_algo(
            client,
            inst_id=inst_id,
            algo_cl_ord_id=independent_algo_id,
            expected_qty=net_qty,
            expected_stop=stop,
            expected_take=take,
            timeout_s=poll_timeout_s,
            interval_s=poll_interval_s,
        )
        if algo.get("algoId"):
            active_id = str(algo["algoId"])
            cleanup_algos.add(active_id)
            cleanup_algo_cl_ids[active_id] = independent_algo_id
        route_b_ok = _algo_is_active(
            algo,
            inst_id=inst_id,
            algo_cl_ord_id=independent_algo_id,
            expected_qty=net_qty,
            expected_stop=stop,
            expected_take=take,
        )
        evidence["independent_oco"] = {
            "algoId": algo.get("algoId"),
            "algoClOrdId": algo.get("algoClOrdId", independent_algo_id),
            "state": algo.get("state"),
            "sz": algo.get("sz"),
            "slTriggerPx": algo.get("slTriggerPx"),
            "tpTriggerPx": algo.get("tpTriggerPx"),
            "transport_error": algo_error,
            "ok": route_b_ok,
        }
        if not route_b_ok:
            raise RuntimeError("独立 OCO 未取得 ACTIVE 交易所事实")

        # 路线 A 只做兼容性探测；无论支持或明确拒绝都形成契约结论，
        # 生产路径仍固定使用上面已经验证的独立 OCO。
        quote_amount = quantity * price * Decimal("1.01")
        attach_stop = _price_on_tick(
            price * Decimal("0.98"),
            tick,
            rounding=ROUND_DOWN,
        )
        attach_take = _price_on_tick(
            price * Decimal("1.02"),
            tick,
            rounding=ROUND_UP,
        )
        attached, attach_error = _place_or_resolve_order(
            client,
            inst_id=inst_id,
            cl_ord_id=attached_order_id,
            size=quote_amount,
            tgt_ccy="quote_ccy",
            timeout_s=poll_timeout_s,
            interval_s=poll_interval_s,
            attach_algo_orders=[{
                "attachAlgoClOrdId": attached_algo_id,
                "tpTriggerPx": text(attach_take),
                "tpOrdPx": "-1",
                "slTriggerPx": text(attach_stop),
                "slOrdPx": "-1",
            }],
        )
        attached_net = _net_base_qty(attached, base_ccy, lot)
        if attached_net > 0:
            cleanup_qty += attached_net
        attached_algo = _find_algo(client, inst_id, attached_algo_id)
        if attached_algo.get("algoId"):
            attached_id = str(attached_algo["algoId"])
            cleanup_algos.add(attached_id)
            cleanup_algo_cl_ids[attached_id] = attached_algo_id
        rejection_code = _attached_rejection_code(attach_error)
        explicitly_rejected = bool(
            rejection_code in ATTACHED_CONTRACT_REJECTION_CODES
            and not attached
        )
        supported = bool(
            attached.get("state") == "filled"
            and attached_net > 0
            and _algo_is_active(
                attached_algo,
                inst_id=inst_id,
                algo_cl_ord_id=attached_algo_id,
                expected_qty=attached_net,
                expected_stop=attach_stop,
                expected_take=attach_take,
            )
        )
        attached_probe_conclusive = supported or explicitly_rejected
        evidence["attached_probe"] = {
            "request_tgt_ccy": "quote_ccy",
            "parent_state": attached.get("state"),
            "parent_ord_id": attached.get("ordId"),
            "algo_id": attached_algo.get("algoId"),
            "algo_state": attached_algo.get("state"),
            "supported": supported,
            "explicitly_rejected": explicitly_rejected,
            "rejection_code": rejection_code,
            "error": attach_error,
            "conclusive": attached_probe_conclusive,
        }
    except Exception as exc:
        evidence["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        for kind in ("oco", "conditional"):
            try:
                rows = client.get_pending_algo_orders(
                    inst_id=inst_id,
                    ord_type=kind,
                )
            except Exception as exc:
                cleanup_errors.append(
                    f"list {kind}: {type(exc).__name__}: {exc}"
                )
                continue
            for row in rows:
                if row.get("algoClOrdId") in {
                    independent_algo_id,
                    attached_algo_id,
                } and row.get("algoId"):
                    cleanup_algos.add(str(row["algoId"]))
        for algo_id in sorted(cleanup_algos):
            try:
                client.cancel_algo_order(inst_id, algo_id)
                cleanup.append({"cancel_algo_id": algo_id})
                inactive, final_algo = _poll_algo_inactive(
                    client,
                    inst_id=inst_id,
                    algo_cl_ord_id=cleanup_algo_cl_ids.get(algo_id, ""),
                    timeout_s=poll_timeout_s,
                    interval_s=poll_interval_s,
                )
                if not inactive:
                    cleanup_errors.append(
                        f"cancel {algo_id}: 保护单仍为 ACTIVE"
                    )
                else:
                    cleanup[-1]["final_state"] = final_algo.get("state")
            except Exception as exc:
                cleanup_errors.append(
                    f"cancel {algo_id}: {type(exc).__name__}: {exc}"
                )
        if cleanup_qty > 0 and not cleanup_errors:
            exit_cl_ord_id = f"cx{nonce}"
            try:
                client.place_order(
                    inst_id,
                    "sell",
                    "market",
                    text(cleanup_qty),
                    tgt_ccy="base_ccy",
                    cl_ord_id=exit_cl_ord_id,
                )
                exit_order = _poll_order(
                    client,
                    inst_id,
                    exit_cl_ord_id,
                    timeout_s=poll_timeout_s,
                    interval_s=poll_interval_s,
                )
                cleanup.append({
                    "exit_ord_id": exit_order.get("ordId"),
                    "state": exit_order.get("state"),
                    "qty": text(cleanup_qty),
                })
                if exit_order.get("state") != "filled":
                    cleanup_errors.append("清理 SELL 未确认完整成交")
            except Exception as exc:
                cleanup_errors.append(
                    f"exit: {type(exc).__name__}: {exc}"
                )
        for kind in ("oco", "conditional"):
            try:
                remaining = client.get_pending_algo_orders(
                    inst_id=inst_id,
                    ord_type=kind,
                )
                if any(
                    row.get("algoClOrdId")
                    in {independent_algo_id, attached_algo_id}
                    for row in remaining
                ):
                    cleanup_errors.append(
                        f"清理后仍存在 pending {kind} algo"
                    )
            except Exception as exc:
                cleanup_errors.append(
                    f"verify {kind}: {type(exc).__name__}: {exc}"
                )
        try:
            pending_orders = client.get_open_orders(inst_id)
            if any(
                row.get("clOrdId")
                in {
                    independent_order_id,
                    attached_order_id,
                    f"cx{nonce}",
                }
                for row in pending_orders
            ):
                cleanup_errors.append("清理后仍存在 pending 普通订单")
        except Exception as exc:
            cleanup_errors.append(
                f"verify orders: {type(exc).__name__}: {exc}"
            )
        try:
            final_base_balance = _base_balance(client, base_ccy)
            evidence["baseline_base_balance"] = text(baseline_base_balance)
            evidence["final_base_balance"] = text(final_base_balance)
            balance_delta = final_base_balance - baseline_base_balance
            evidence["final_base_balance_delta"] = text(balance_delta)
            balance_tolerance = lot / Decimal("1000")
            if abs(balance_delta) > balance_tolerance:
                cleanup_errors.append(
                    "清理后基础币余额未回到基线，可能残留或侵蚀原有持仓"
                )
        except Exception as exc:
            cleanup_errors.append(
                f"verify balance: {type(exc).__name__}: {exc}"
            )
        evidence["cleanup_errors"] = cleanup_errors
        evidence["completed_at"] = time.time()
        evidence["route_b_ok"] = route_b_ok
        evidence["attached_probe_conclusive"] = attached_probe_conclusive
        evidence["ok"] = (
            route_b_ok
            and attached_probe_conclusive
            and not cleanup_errors
        )
    return evidence, bool(evidence["ok"])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--inst", default="BTC-USDT")
    parser.add_argument("--confirm", required=True)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("demo-contract-evidence.json"),
    )
    parser.add_argument(
        "--fixture-output",
        type=Path,
        help="可选：输出版本化、稳定 ID 脱敏后的 OKX demo golden fixture",
    )
    args = parser.parse_args()
    if args.confirm != CONFIRMATION:
        raise SystemExit(f"--confirm 必须精确等于 {CONFIRMATION}")
    if args.output.exists():
        raise SystemExit(f"拒绝覆盖既有 contract evidence: {args.output}")
    if args.fixture_output is not None and args.fixture_output.exists():
        raise SystemExit(
            f"拒绝覆盖既有 contract fixture: {args.fixture_output}"
        )
    config = load_yaml(args.config)
    if config.get("okx", {}).get("simulated") is not True:
        raise SystemExit("拒绝执行：该脚本只允许 okx.simulated=true")
    evidence, ok = run_contract(make_client(config), args.inst)
    args.output.write_text(
        json.dumps(evidence, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    if ok and args.fixture_output is not None:
        fixture = build_redacted_contract_fixture(evidence)
        args.fixture_output.write_text(
            json.dumps(fixture, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    print(json.dumps(evidence, ensure_ascii=False))
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main())
