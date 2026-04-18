"""账户持仓恢复 —— 单一实现

根据交易所账户快照，把非计价币种的已有持仓登记到 RiskManager，
并可选地把对应 inst_id 返回给调用方用于扩展交易列表。
"""

from __future__ import annotations

import logging
import time

from okx_quant.exchange import Exchange
from okx_quant.risk.manager import PositionInfo, RiskManager

logger = logging.getLogger(__name__)


def discover_positions(
    exchange: Exchange,
    quote_ccy: str = "USDT",
    *,
    min_usdt_value: float = 1.0,
) -> list[tuple[str, float]]:
    """扫描账户余额，返回非计价币种持仓列表 [(inst_id, balance), ...]。

    粉尘过滤：余额折算后低于 ``min_usdt_value`` 的持仓会被跳过，
    避免 OKX 账户里残留的 token dust（0.000xxx ENA/APT/CFX 等）
    被误认为真实仓位而占用 instrument slot。

    仅读取交易所状态，不修改任何内部状态。
    """
    try:
        snap = exchange.get_balance()
    except Exception as e:  # noqa: BLE001
        logger.warning("检测已有持仓失败: %s", e)
        return []
    results: list[tuple[str, float]] = []
    for holding in snap.non_quote_holdings(quote_ccy):
        inst_id = f"{holding.ccy}-{quote_ccy}"
        # 查 ticker 估算 USDT 价值 → 过滤粉尘
        # price<=0 视为 ticker 不可靠，保守保留（后续 restore_to_risk 还会二次过滤）
        if min_usdt_value > 0:
            try:
                price = exchange.get_ticker(inst_id).last
                if price > 0:
                    value_usdt = holding.balance * price
                    if value_usdt < min_usdt_value:
                        logger.info(
                            "忽略粉尘持仓 %s（%.8f × $%.6f = $%.6f < $%.2f）",
                            inst_id, holding.balance, price, value_usdt, min_usdt_value,
                        )
                        continue
            except Exception:  # noqa: BLE001
                pass
        results.append((inst_id, holding.balance))
    return results


def restore_to_risk(
    exchange: Exchange,
    risk: RiskManager,
    inst_ids: "list[str] | set[str]",
    *,
    quote_ccy: str = "USDT",
    min_usdt_value: float = 1.0,
) -> int:
    """把在 inst_ids 范围内且已存在余额的持仓登记到 RiskManager。

    - 只恢复 risk 中尚未记录的 inst_id，避免重复登记
    - 入场价使用当前 ticker 估算（无法拿到真实入场价）
    - 止损/止盈按 risk.config 的默认比例计算

    Returns:
        成功恢复的持仓数量
    """
    inst_set = set(inst_ids)
    if not inst_set:
        return 0

    try:
        snap = exchange.get_balance()
    except Exception as e:  # noqa: BLE001
        logger.warning("恢复持仓失败（获取余额）: %s", e)
        return 0

    t0 = time.perf_counter()
    restored = 0
    for holding in snap.non_quote_holdings(quote_ccy):
        inst_id = f"{holding.ccy}-{quote_ccy}"
        if inst_id not in inst_set:
            continue
        if risk.has_position(inst_id):
            continue
        try:
            price = exchange.get_ticker(inst_id).last
        except Exception:  # noqa: BLE001
            price = 0.0
        if price <= 0:
            logger.debug("恢复持仓跳过 %s：ticker 取不到价格", inst_id)
            continue

        # 使用 available（非锁定余额）作为可卖数量；cashBal 包含冻结部分，
        # 作为仓位登记会高估可平数量
        size = holding.available if holding.available > 0 else holding.balance

        # 粉尘过滤：总价值 < min_usdt_value 的忽略（OKX 账户残留）
        if min_usdt_value > 0 and size * price < min_usdt_value:
            logger.info(
                "忽略粉尘持仓 %s（%.8f × $%.6f = $%.6f < $%.2f）",
                inst_id, size, price, size * price, min_usdt_value,
            )
            continue

        sl = round(price * (1 - risk.config.stop_loss_pct), 8)
        tp = round(price * (1 + risk.config.take_profit_pct), 8)
        risk.add_position(PositionInfo(
            inst_id=inst_id,
            size=size,
            entry_price=price,
            stop_loss=sl,
            take_profit=tp,
        ))
        logger.info(
            "恢复已有持仓: %s  数量=%.6f  参考价=%.4f（估算）",
            inst_id, size, price,
        )
        restored += 1
    elapsed = time.perf_counter() - t0
    if restored > 0 and elapsed > 2.0:
        logger.warning(
            "恢复 %d 个持仓耗时 %.1fs —— 单独拉 ticker 过慢，考虑批量接口",
            restored, elapsed,
        )
    return restored
