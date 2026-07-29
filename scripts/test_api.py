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
from decimal import ROUND_DOWN, ROUND_UP, Decimal

import requests

# 项目根目录加入 sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from main import load_env_file
from okx_quant.client.rest import OKXRestClient
from okx_quant.config import load_yaml

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

def load_config(path: str = "config.yaml") -> dict:
    if not os.path.exists(path):
        print(f"{_RED}错误: 找不到 {path}，请从 config.yaml.example 复制并填写{_RESET}")
        sys.exit(1)
    return load_yaml(path)


# ── 测试步骤 ─────────────────────────────────────────────

def test_connectivity(client: OKXRestClient, inst_id: str) -> bool:
    """测试 1: 公共接口连通性"""
    _header("测试 1: 网络连通性（公共接口）")

    # 1a. 服务器时间
    try:
        t0 = time.time()
        data = client.get("/api/v5/public/time")
        latency = (time.time() - t0) * 1000
        server_time = int(data[0]["ts"]) / 1000
        skew_ms = abs(time.time() - server_time) * 1000
        _ok(
            f"服务器时间获取成功  延迟={latency:.0f}ms "
            f"时钟偏差={skew_ms:.0f}ms"
        )
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

    missing = [
        name
        for name, value in (
            ("OKX_API_KEY", client.api_key),
            ("OKX_SECRET_KEY", client.secret_key),
            ("OKX_PASSPHRASE", client.passphrase),
        )
        if not value
    ]
    if missing:
        _warn("鉴权变量未完整加载，跳过私有接口")
        _info("缺失: " + ", ".join(missing))
        _info("请在同一终端导出 Demo Key/Secret/Passphrase 后重试")
        return False, 0.0

    mode = "模拟盘" if client.simulated else "实盘"
    _info(f"当前模式: {mode}")
    _info(f"API 域名: {client.base_url}")

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
    except requests.HTTPError as e:
        _fail(f"API 鉴权 HTTP 失败: {e}")
        if e.response is not None and e.response.status_code == 401:
            _info("请依次检查：")
            _info("1. Key 是否在 OKX Demo Trading 页面单独创建")
            _info("2. Secret 与 Passphrase 是否属于同一把 Demo Key")
            _info("3. 账户注册区域是否要求 us.okx.com/eea.okx.com")
            _info("4. Key 的 IP 白名单是否包含当前出口 IP")
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

    仅模拟盘: 市价买入 → 查询 → 卖出（约 1 USDT）
    """
    _header("测试 3: 交易能力（下单测试）")

    if client.simulated:
        return _test_trade_simulated(client, inst_id, available)
    _fail(
        "--trade 严格禁止实盘写操作；实盘只能使用持久化 "
        "ProductionRuntime/控制面"
    )
    return False


def _test_trade_live(client: OKXRestClient, inst_id: str) -> bool:
    """保留兼容入口，但任何实盘调用都 fail closed。"""
    del client, inst_id
    raise RuntimeError(
        "scripts/test_api.py 禁止实盘写；使用 ProductionRuntime"
    )


def _decimal(value: object, default: str = "0") -> Decimal:
    try:
        return Decimal(str(value or default))
    except Exception:
        return Decimal(default)


def _net_base_size(order: dict, base_ccy: str, lot_size: Decimal) -> Decimal:
    """Return the sellable base quantity after base-currency fees."""
    filled = _decimal(order.get("accFillSz") or order.get("fillSz"))
    fee = _decimal(order.get("fee"))
    if str(order.get("feeCcy", "")).upper() == base_ccy.upper():
        filled += fee
    net = max(filled, Decimal("0"))
    return (net / lot_size).to_integral_value(rounding=ROUND_DOWN) * lot_size


def _decimal_text(value: Decimal) -> str:
    return format(value.normalize(), "f")


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

    try:
        instrument = client.get_instrument(inst_id)
        base_ccy = str(instrument.get("baseCcy") or inst_id.split("-", 1)[0])
        lot_size = _decimal(instrument.get("lotSz"), "0.00000001")
        min_size = _decimal(instrument.get("minSz"), "0")
        if lot_size <= 0:
            raise ValueError("lotSz 必须大于 0")
    except Exception as e:
        _fail(f"读取交易品种规则失败: {e}")
        return False

    # 计算符合交易品种 lotSz/minSz 的最小下单量（约 1 USDT）
    min_usdt = Decimal("1")
    required_size = max(min_usdt / Decimal(str(price)), min_size)
    size = (
        required_size / lot_size
    ).to_integral_value(rounding=ROUND_UP) * lot_size
    size_str = _decimal_text(size)
    estimated_notional = size * Decimal(str(price))

    if Decimal(str(available)) < estimated_notional:
        _warn(
            f"可用余额 {available:.2f} USDT 不足 "
            f"{_decimal_text(estimated_notional)} USDT，跳过下单测试"
        )
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
            tgt_ccy="base_ccy",
        )
        ord_id = result.get("ordId", "")
        _ok(f"买入下单成功  ordId={ord_id}")
    except Exception as e:
        _fail(f"买入下单失败: {e}")
        _info("可能原因: 最小下单量限制 / 账户模式不匹配 / 交易对不可用")
        return False

    # 3b. 查询订单状态
    order = None
    for _ in range(5):
        time.sleep(1)
        try:
            order = client.get_order(inst_id, ord_id)
        except Exception as e:
            _warn(f"订单查询失败: {e}")
            continue
        if order.get("state") in {"filled", "canceled"}:
            break

    if not order:
        _fail("无法确认买入订单状态，不能安全计算平仓数量")
        _info("请手动检查模拟盘持仓")
        return False

    state = str(order.get("state", "unknown"))
    fill_sz = order.get("accFillSz") or order.get("fillSz", "0")
    avg_px = order.get("avgPx", "0")
    if state != "filled":
        _fail(f"买入订单未完整成交  状态={state}  成交量={fill_sz}")
        _info("请手动检查模拟盘持仓和挂单")
        return False
    _ok(f"订单查询成功  状态={state}  成交量={fill_sz}  均价={avg_px}")

    # 3c. 市价卖出（平仓）
    actual_size = _net_base_size(order, base_ccy, lot_size)
    if actual_size < min_size or actual_size <= 0:
        _fail(
            "扣除基础币手续费后的可卖数量低于最小下单量 "
            f"(可卖={_decimal_text(actual_size)}, minSz={_decimal_text(min_size)})"
        )
        _info("请手动检查模拟盘持仓")
        return False

    try:
        sell_result = client.place_order(
            inst_id=inst_id,
            side="sell",
            ord_type="market",
            sz=_decimal_text(actual_size),
        )
        sell_id = str(sell_result.get("ordId", ""))
        if not sell_id:
            raise RuntimeError("卖出响应缺少 ordId")
        _ok(
            f"卖出下单成功  ordId={sell_id} "
            f"净数量={_decimal_text(actual_size)}"
        )
    except Exception as e:
        _fail(f"卖出失败: {e}")
        _info("请手动检查模拟盘持仓")
        return False

    sell_order = None
    for _ in range(5):
        time.sleep(1)
        try:
            sell_order = client.get_order(inst_id, sell_id)
        except Exception as e:
            _warn(f"卖出订单查询失败: {e}")
            continue
        if sell_order.get("state") in {"filled", "canceled"}:
            break
    sell_state = str((sell_order or {}).get("state", "unknown"))
    if sell_state != "filled":
        _fail(f"无法确认卖出订单完整成交  状态={sell_state}")
        _info("请手动检查模拟盘持仓和挂单")
        return False
    _ok(f"卖出订单确认成交  状态={sell_state}")

    return True


# ── 主流程 ───────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="OKX API 连通性与交易能力诊断")
    parser.add_argument("--config", default="config.yaml", help="配置文件路径")
    parser.add_argument(
        "--env-file",
        default="",
        help="安全读取 KEY=VALUE 环境文件（不执行 shell）",
    )
    parser.add_argument("--trade", action="store_true", help="执行模拟盘交易测试（买入→卖出）")
    parser.add_argument("--inst", default="DOGE-USDT", help="测试交易对 (默认 DOGE-USDT)")
    args = parser.parse_args()

    print(f"\n{_BOLD}OKX API 诊断工具{_RESET}")
    print(f"交易对: {args.inst}")

    load_env_file(args.env_file)
    cfg = load_config(args.config)
    okx_cfg = cfg.get("okx", {})
    client = OKXRestClient(
        api_key=okx_cfg.get("api_key", ""),
        secret_key=okx_cfg.get("secret_key", ""),
        passphrase=okx_cfg.get("passphrase", ""),
        simulated=okx_cfg.get("simulated", True),
        base_url=okx_cfg.get("base_url", ""),
        proxy=okx_cfg.get("proxy", ""),
        timeout=int(okx_cfg.get("timeout", 10)),
        max_retries=int(okx_cfg.get("max_retries", 3)),
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
    if not all(results.values()):
        sys.exit(1)


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
