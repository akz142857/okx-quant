#!/usr/bin/env python3
"""OKX API 连通性与交易能力诊断脚本

逐步检测：
  1. 网络连通性（公共行情接口）
  2. API 鉴权（账户余额查询）
  3. 交易能力（模拟盘小额买入 → 查询 → 撤单/卖出）

用法:
    uv run python scripts/test_api.py                # 仅检测连通性 + 鉴权
    uv run python scripts/test_api.py --trade         # 额外执行模拟盘交易测试
    uv run python scripts/test_api.py --inst ETH-USDT # 指定交易对
"""

import argparse
import os
import sys
import time

# 项目根目录加入 sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import yaml
from okx_quant.client.rest import OKXRestClient


# ── 输出辅助 ──────────────────────────────────────────────

_GREEN = "\033[92m"
_RED = "\033[91m"
_YELLOW = "\033[93m"
_CYAN = "\033[96m"
_DIM = "\033[2m"
_RESET = "\033[0m"
_BOLD = "\033[1m"


def _ok(msg: str):
    print(f"  {_GREEN}✔{_RESET} {msg}")


def _fail(msg: str):
    print(f"  {_RED}✘{_RESET} {msg}")


def _warn(msg: str):
    print(f"  {_YELLOW}⚠{_RESET} {msg}")


def _info(msg: str):
    print(f"  {_DIM}{msg}{_RESET}")


def _header(title: str):
    print(f"\n{_CYAN}{_BOLD}{'─'*50}")
    print(f"  {title}")
    print(f"{'─'*50}{_RESET}\n")


# ── 加载配置 ─────────────────────────────────────────────

def load_config() -> dict:
    path = "config.yaml"
    if not os.path.exists(path):
        print(f"{_RED}错误: 找不到 {path}，请从 config.yaml.example 复制并填写{_RESET}")
        sys.exit(1)
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


# ── 测试步骤 ─────────────────────────────────────────────

def test_connectivity(client: OKXRestClient, inst_id: str) -> bool:
    """测试 1: 公共接口连通性"""
    _header("测试 1: 网络连通性（公共接口）")

    # 1a. 服务器时间
    try:
        t0 = time.time()
        data = client.get("/api/v5/public/time")
        latency = (time.time() - t0) * 1000
        server_ts = int(data[0]["ts"])
        _ok(f"服务器时间获取成功  延迟={latency:.0f}ms")
    except Exception as e:
        _fail(f"无法连接 OKX 服务器: {e}")
        _info("请检查网络/VPN/代理设置")
        return False

    # 1b. 获取行情
    try:
        ticker = client.get_ticker(inst_id)
        price = float(ticker.get("last", 0))
        _ok(f"{inst_id} 最新价: ${price:,.6f}")
    except Exception as e:
        _fail(f"获取 {inst_id} 行情失败: {e}")
        return False

    # 1c. 获取 K 线
    try:
        candles = client.get_candles(inst_id, bar="1m", limit=5)
        _ok(f"K 线数据获取成功  返回 {len(candles)} 根")
    except Exception as e:
        _fail(f"获取 K 线失败: {e}")
        return False

    return True


def test_auth(client: OKXRestClient) -> tuple[bool, float]:
    """测试 2: API 鉴权（私有接口）"""
    _header("测试 2: API 鉴权（私有接口）")

    if not client.api_key:
        _warn("未配置 API Key，跳过鉴权测试")
        _info("请在 config.yaml 中填写 okx.api_key / secret_key / passphrase")
        return False, 0.0

    mode = "模拟盘" if client.simulated else "实盘"
    _info(f"当前模式: {mode}")

    # 2a. 查询账户余额
    try:
        balances = client.get_balance("USDT")
        equity = 0.0
        available = 0.0
        for item in balances:
            for detail in item.get("details", []):
                if detail.get("ccy") == "USDT":
                    equity = float(detail.get("eq", 0))
                    available = float(detail.get("availEq", 0) or detail.get("availBal", 0) or 0)
        _ok(f"账户余额查询成功  权益={equity:.2f} USDT  可用={available:.2f} USDT")
    except ValueError as e:
        _fail(f"鉴权配置错误: {e}")
        return False, 0.0
    except RuntimeError as e:
        _fail(f"API 鉴权失败: {e}")
        _info("请检查 API Key / Secret / Passphrase 是否正确")
        if client.simulated:
            _info("模拟盘需要在 OKX 官网单独申请模拟盘 API Key")
        return False, 0.0
    except Exception as e:
        _fail(f"查询余额异常: {e}")
        return False, 0.0

    # 2b. 查询持仓
    try:
        positions = client.get_open_orders()
        _ok(f"未成交订单查询成功  当前挂单数={len(positions)}")
    except Exception as e:
        _warn(f"查询未成交订单失败: {e}")

    if equity == 0 and available == 0:
        _warn("账户余额为 0，交易测试将无法执行")
        _info("模拟盘请先到 OKX 官网模拟盘页面领取测试资金")

    return True, available


def test_trade(client: OKXRestClient, inst_id: str, available: float) -> bool:
    """测试 3: 下单能力测试

    模拟盘: 市价买入 → 查询 → 卖出（约 1 USDT）
    实  盘: 限价挂单（远低于市价，不会成交）→ 查询 → 立即撤单
    """
    _header("测试 3: 交易能力（下单测试）")

    if client.simulated:
        return _test_trade_simulated(client, inst_id, available)
    else:
        return _test_trade_live(client, inst_id)


def _test_trade_live(client: OKXRestClient, inst_id: str) -> bool:
    """实盘安全测试: 限价挂单（不会成交）→ 查询 → 撤单"""
    _info("实盘模式 — 使用限价挂单 + 立即撤单测试，不会实际成交")

    # 获取当前价格
    try:
        ticker = client.get_ticker(inst_id)
        price = float(ticker.get("last", 0))
    except Exception as e:
        _fail(f"获取价格失败: {e}")
        return False

    if price <= 0:
        _fail("价格异常，无法测试")
        return False

    # 挂一个远低于市价 50% 的限价买单，绝不会成交
    test_price = price * 0.5
    # 计算最小下单量（约 1 USDT）
    min_usdt = 1.0
    size = min_usdt / test_price
    size_str = f"{size:.4f}" if test_price < 1 else f"{size:.8f}".rstrip("0").rstrip(".")
    px_str = f"{test_price:.6f}" if test_price < 1 else f"{test_price:.4f}"

    _info(f"挂限价买单: 价格=${px_str}（市价的50%，不会成交）数量={size_str}")

    # 3a. 限价挂单
    ord_id = ""
    try:
        result = client.place_order(
            inst_id=inst_id,
            side="buy",
            ord_type="limit",
            sz=size_str,
            px=px_str,
        )
        ord_id = result.get("ordId", "")
        _ok(f"限价挂单成功  ordId={ord_id}")
    except Exception as e:
        _fail(f"挂单失败: {e}")
        _info("可能原因: 最小下单量限制 / 账户模式不匹配 / IP 白名单限制")
        return False

    # 3b. 查询订单
    time.sleep(0.5)
    try:
        order = client.get_order(inst_id, ord_id)
        state = order.get("state", "unknown")
        _ok(f"订单查询成功  状态={state}")
    except Exception as e:
        _warn(f"订单查询失败: {e}")

    # 3c. 立即撤单
    try:
        client.cancel_order(inst_id, ord_id)
        _ok("撤单成功  无资金变动")
    except Exception as e:
        _fail(f"撤单失败: {e}")
        _info(f"请手动撤销订单 ordId={ord_id}")
        return False

    return True


def _test_trade_simulated(client: OKXRestClient, inst_id: str, available: float) -> bool:
    """模拟盘测试: 市价买入 → 查询 → 卖出"""
    _info("模拟盘模式 — 执行市价买入 + 卖出测试")

    # 获取当前价格
    try:
        ticker = client.get_ticker(inst_id)
        price = float(ticker.get("last", 0))
    except Exception as e:
        _fail(f"获取价格失败: {e}")
        return False

    if price <= 0:
        _fail("价格异常，无法测试")
        return False

    # 计算最小下单量（约 1 USDT）
    min_usdt = 1.0
    size = min_usdt / price
    size_str = f"{size:.4f}" if price < 1 else f"{size:.8f}".rstrip("0").rstrip(".")

    if available < min_usdt:
        _warn(f"可用余额 {available:.2f} USDT 不足 {min_usdt} USDT，跳过下单测试")
        _info("模拟盘请到 OKX 官网领取测试资金")
        return False

    _info(f"将买入约 {min_usdt} USDT 的 {inst_id} (数量={size_str}, 价格≈${price:.6f})")

    # 3a. 市价买入
    ord_id = ""
    try:
        result = client.place_order(
            inst_id=inst_id,
            side="buy",
            ord_type="market",
            sz=size_str,
        )
        ord_id = result.get("ordId", "")
        _ok(f"买入下单成功  ordId={ord_id}")
    except Exception as e:
        _fail(f"买入下单失败: {e}")
        _info("可能原因: 最小下单量限制 / 账户模式不匹配 / 交易对不可用")
        return False

    # 3b. 查询订单状态
    time.sleep(1)
    order = None
    try:
        order = client.get_order(inst_id, ord_id)
        state = order.get("state", "unknown")
        fill_sz = order.get("fillSz", "0")
        avg_px = order.get("avgPx", "0")
        _ok(f"订单查询成功  状态={state}  成交量={fill_sz}  均价={avg_px}")
    except Exception as e:
        _warn(f"订单查询失败: {e}")

    # 3c. 市价卖出（平仓）
    try:
        actual_size = order.get("fillSz", size_str) if order else size_str
        if float(actual_size) > 0:
            sell_result = client.place_order(
                inst_id=inst_id,
                side="sell",
                ord_type="market",
                sz=actual_size,
            )
            sell_id = sell_result.get("ordId", "")
            _ok(f"卖出下单成功  ordId={sell_id}")
        else:
            _warn("买入未成交，跳过卖出")
    except Exception as e:
        _warn(f"卖出失败: {e}")
        _info("请手动检查模拟盘持仓")

    return True


# ── 主流程 ───────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="OKX API 连通性与交易能力诊断")
    parser.add_argument("--trade", action="store_true", help="执行模拟盘交易测试（买入→卖出）")
    parser.add_argument("--inst", default="DOGE-USDT", help="测试交易对 (默认 DOGE-USDT)")
    args = parser.parse_args()

    print(f"\n{_BOLD}OKX API 诊断工具{_RESET}")
    print(f"交易对: {args.inst}")

    cfg = load_config()
    okx_cfg = cfg.get("okx", {})
    client = OKXRestClient(
        api_key=okx_cfg.get("api_key", ""),
        secret_key=okx_cfg.get("secret_key", ""),
        passphrase=okx_cfg.get("passphrase", ""),
        simulated=okx_cfg.get("simulated", True),
        timeout=10,
    )

    results = {}

    # 测试 1: 连通性
    results["connectivity"] = test_connectivity(client, args.inst)
    if not results["connectivity"]:
        _print_summary(results)
        sys.exit(1)

    # 测试 2: 鉴权
    auth_ok, available = test_auth(client)
    results["auth"] = auth_ok

    # 测试 3: 交易（需 --trade 参数）
    if args.trade:
        if not auth_ok:
            _warn("鉴权失败，跳过交易测试")
            results["trade"] = False
        else:
            results["trade"] = test_trade(client, args.inst, available)

    _print_summary(results)


def _print_summary(results: dict):
    _header("诊断结果汇总")

    labels = {
        "connectivity": "网络连通",
        "auth": "API 鉴权",
        "trade": "交易能力",
    }
    all_pass = True
    for key, label in labels.items():
        if key not in results:
            continue
        if results[key]:
            _ok(label)
        else:
            _fail(label)
            all_pass = False

    print()
    if all_pass:
        print(f"  {_GREEN}{_BOLD}所有测试通过 ✔{_RESET}\n")
    else:
        print(f"  {_YELLOW}部分测试未通过，请根据上方提示排查{_RESET}\n")


if __name__ == "__main__":
    main()
