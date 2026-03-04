"""实盘交易仪表盘 — ANSI 终端面板，每 tick 重绘"""

import os
import sys
import shutil
from dataclasses import dataclass, field
from datetime import datetime

from okx_quant.cli.colors import (
    bold, cyan, dim, green, red, yellow, gray,
    colored_pnl, colored_pnl_pct, colored_signal, colored_regime,
)


@dataclass
class TradeRecord:
    """单笔交易记录"""
    time: str
    side: str       # "BUY" / "SELL"
    price: float
    size: float
    coin: str
    pnl: str = ""   # 卖出时的盈亏文本


@dataclass
class DashboardState:
    """一帧仪表盘所需的全部数据"""
    # 基本信息
    inst_id: str = ""
    strategy_name: str = ""
    bar: str = ""
    simulated: bool = True
    start_time: datetime = field(default_factory=datetime.now)

    # 账户
    equity: float = 0.0
    available: float = 0.0
    account_pnl: float = 0.0
    account_pnl_pct: float = 0.0

    # 持仓
    position_size: float = 0.0
    position_coin: str = ""
    entry_price: float = 0.0
    current_price: float = 0.0
    position_pnl: float = 0.0
    position_pnl_pct: float = 0.0
    stop_loss: float = 0.0
    take_profit: float = 0.0

    # 风控
    drawdown_pct: float = 0.0
    max_drawdown_pct: float = 15.0
    open_positions: int = 0
    max_positions: int = 1
    risk_halted: bool = False

    # 信号
    signal_name: str = "HOLD"
    signal_reason: str = ""
    signal_time: str = ""

    # 策略指标（来自 signal.extra）
    indicators: dict = field(default_factory=dict)

    # 交易记录
    recent_trades: list[TradeRecord] = field(default_factory=list)

    # 轮询信息
    countdown: int = 0
    tick_count: int = 0
    last_update: str = ""


class Dashboard:
    """终端仪表盘渲染器"""

    def __init__(self):
        self._first_render = True
        self._event_lines: list[str] = []
        self._is_tty = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()
        self._panel_height = 0

    def render(self, state: DashboardState):
        """重绘整个面板"""
        if not self._is_tty:
            self._render_plain(state)
            return

        cols = shutil.get_terminal_size((80, 24)).columns
        w = min(cols, 60)

        lines = self._build_panel(state, w)
        self._panel_height = len(lines)

        if self._first_render:
            sys.stdout.write("\033[2J\033[H")
            self._first_render = False
        else:
            sys.stdout.write("\033[H")

        for line in lines:
            sys.stdout.write(line + "\n")

        # 事件日志区
        if self._event_lines:
            sys.stdout.write("\n")
            for ev in self._event_lines[-10:]:
                sys.stdout.write(ev + "\n")

        # 清除剩余行
        sys.stdout.write("\033[J")
        sys.stdout.flush()

    def log_event(self, msg: str):
        """追加事件日志行"""
        ts = datetime.now().strftime("%H:%M:%S")
        line = f"[{ts}] {msg}"
        self._event_lines.append(line)
        if not self._is_tty:
            print(line, flush=True)

    def _build_panel(self, s: DashboardState, w: int) -> list[str]:
        """构建面板行列表"""
        mode = "【模拟】" if s.simulated else "【实盘】"
        elapsed = self._elapsed(s.start_time)
        start_str = s.start_time.strftime("%m-%d %H:%M")
        coin = s.inst_id.split("-")[0] if s.inst_id else ""

        # 内容宽度 = w - 3（左边 "│ " 占 2，右边 "│" 占 1）
        cw = w - 3
        # 双列布局：左列宽度、右列宽度
        lw = cw // 2
        rw = cw - lw

        lines: list[str] = []
        hr = "─" * (w - 2)

        def row(text: str):
            visible = _strip_ansi(text)
            dw = _display_width(visible)
            if dw > cw:
                text = _truncate_to_width(text, cw)
                dw = _display_width(_strip_ansi(text))
            pad = cw - dw
            lines.append(f"│ {text}{' ' * pad}│")

        def row2(left: str, right: str):
            """双列行：左列 + 右列，分别补齐到各自宽度"""
            left_padded = _pad_right(left, lw)
            right_padded = _pad_right(right, rw)
            lines.append(f"│ {left_padded}{right_padded}│")

        # 标题
        lines.append(f"┌{hr}┐")
        title = " OKX 实盘交易 "
        left_dashes = (w - 2 - _display_width(title)) // 2
        right_dashes = w - 2 - left_dashes - _display_width(title)
        lines.append(f"│{'─' * left_dashes}{title}{'─' * right_dashes}│")

        row(f"{bold(s.inst_id)}  策略: {s.strategy_name}  周期: {s.bar}  {mode}")
        row(f"启动: {start_str}    运行: {elapsed}")

        # 账户 + 持仓
        lines.append(f"├{hr}┤")
        row2("账户", "持仓")
        row2(
            f" 权益: {s.equity:.2f} USDT",
            f" 数量: {s.position_size:.4f} {coin}",
        )
        row2(
            f" 可用: {s.available:.2f} USDT",
            f" 入场: ${s.entry_price:.4f}",
        )

        acct_pnl = colored_pnl(s.account_pnl)
        acct_pct = colored_pnl_pct(s.account_pnl_pct)
        pos_pnl = colored_pnl(s.position_pnl)
        pos_pct = colored_pnl_pct(s.position_pnl_pct)

        row2(
            f" 盈亏: {acct_pnl} ({acct_pct})",
            f" 现价: ${s.current_price:.4f}",
        )
        if s.position_size > 0:
            row2("", f" 盈亏: {pos_pnl} ({pos_pct})")
            if s.stop_loss > 0:
                sl_pct = (s.stop_loss / s.entry_price - 1) * 100 if s.entry_price else 0
                tp_pct = (s.take_profit / s.entry_price - 1) * 100 if s.entry_price else 0
                row2(
                    "",
                    f" 止损: ${s.stop_loss:.4f} ({sl_pct:+.1f}%)",
                )
                row2(
                    "",
                    f" 止盈: ${s.take_profit:.4f} ({tp_pct:+.1f}%)",
                )

        # 风控 + 信号
        lines.append(f"├{hr}┤")
        risk_status = red("暂停") if s.risk_halted else green("正常")
        sig = colored_signal(s.signal_name)
        row2("风控", "信号")
        row2(f" 回撤: {s.drawdown_pct:.1f}%", f" 最新: {sig}")
        row2(f" 上限: {s.max_drawdown_pct:.1f}%", f" 原因: {s.signal_reason}")
        row2(f" 持仓: {s.open_positions}/{s.max_positions}", f" 时间: {s.signal_time}")
        row2(f" 状态: {risk_status}", "")

        # 指标
        ind = s.indicators
        if ind:
            lines.append(f"├{hr}┤")
            # Bollinger 指标
            if "pct_b" in ind:
                pct_b = ind["pct_b"]
                rsi_val = ind.get("rsi", 0)
                lower = ind.get("lower", 0)
                upper = ind.get("upper", 0)
                middle = ind.get("middle", 0)
                row2(bold("指标"), bold("布林带"))
                row2(f" %B: {pct_b:.1f}", f" 上轨: ${upper:.6f}")
                row2(f" RSI: {rsi_val:.1f}", f" 中轨: ${middle:.6f}")
                row2(f" 买入触发: %B≤0 且 RSI<40", f" 下轨: ${lower:.6f}")
            # MA Cross 指标
            elif "fast_ma" in ind:
                fast = ind["fast_ma"]
                slow = ind["slow_ma"]
                atr_val = ind.get("atr", 0)
                gap_pct = ind.get("gap_pct", 0)
                gap_color = green(f"{gap_pct:+.2f}%") if gap_pct > 0 else red(f"{gap_pct:+.2f}%")
                row2(bold("指标"), bold("均线"))
                row2(f" EMA快: ${fast:.6f}", f" 差值: {gap_color}")
                row2(f" EMA慢: ${slow:.6f}", f" ATR: ${atr_val:.6f}")
                if gap_pct < 0:
                    row2(f" 买入触发: 快线上穿慢线", "")
                else:
                    row2(f" 卖出触发: 快线下穿慢线", "")
            # Adaptive 策略指标
            elif "regime" in ind:
                regime_label = ind.get("regime", "")
                adx_val = ind.get("adx", 0)
                bw_val = ind.get("bandwidth", 0)
                plus_di = ind.get("plus_di", 0)
                minus_di = ind.get("minus_di", 0)
                sub = ind.get("sub_strategy", "")
                row2(bold("指标"), bold("市场状态"))
                row2(f" ADX: {adx_val:.1f}", f" 状态: {colored_regime(regime_label)}")
                row2(f" +DI: {plus_di:.1f}", f" 带宽: {bw_val:.1f}")
                row2(f" -DI: {minus_di:.1f}", f" 子策略: {sub}")

        # 最近交易
        if s.recent_trades:
            lines.append(f"├{hr}┤")
            row(bold("最近交易"))
            for t in s.recent_trades[-5:]:
                side_str = colored_signal(t.side)
                pnl_str = f"  {t.pnl}" if t.pnl else ""
                row(f" {t.time}  {side_str}  ${t.price:.4f}  {t.size:.4f} {t.coin}{pnl_str}")

        # 底栏
        lines.append(f"├{hr}┤")
        row(f"下次轮询: {s.countdown}s   轮次: #{s.tick_count}   更新: {s.last_update}")
        lines.append(f"└{hr}┘")

        return lines

    def _render_plain(self, state: DashboardState):
        """非 TTY 降级为单行日志"""
        sig = state.signal_name
        print(
            f"[#{state.tick_count}] {state.inst_id} "
            f"价格=${state.current_price:.4f} "
            f"信号={sig} "
            f"权益={state.equity:.2f} "
            f"回撤={state.drawdown_pct:.1f}%",
            flush=True,
        )

    @staticmethod
    def _elapsed(start: datetime) -> str:
        return _elapsed(start)


@dataclass
class MultiDashboardState:
    """多币种仪表盘一帧所需的全部数据"""
    # 基本信息
    strategy_name: str = ""
    bar: str = ""
    simulated: bool = True
    start_time: datetime = field(default_factory=datetime.now)

    # 账户（全局共享）
    equity: float = 0.0
    available: float = 0.0
    account_pnl: float = 0.0
    account_pnl_pct: float = 0.0

    # 风控（全局共享）
    drawdown_pct: float = 0.0
    max_drawdown_pct: float = 15.0
    open_positions: int = 0
    max_positions: int = 1
    risk_halted: bool = False

    # 各 worker 状态
    worker_states: list[dict] = field(default_factory=list)

    # 合并的交易记录
    recent_trades: list[TradeRecord] = field(default_factory=list)

    # 轮询信息
    tick_count: int = 0
    last_update: str = ""


class MultiDashboard:
    """多币种终端仪表盘渲染器"""

    def __init__(self):
        self._first_render = True
        self._is_tty = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

    def render(self, state: MultiDashboardState):
        if not self._is_tty:
            self._render_plain(state)
            return

        cols = shutil.get_terminal_size((80, 24)).columns
        w = min(cols, 76)
        lines = self._build_panel(state, w)

        if self._first_render:
            sys.stdout.write("\033[2J\033[H")
            self._first_render = False
        else:
            sys.stdout.write("\033[H")

        for line in lines:
            sys.stdout.write(line + "\n")

        sys.stdout.write("\033[J")
        sys.stdout.flush()

    def _build_panel(self, s: MultiDashboardState, w: int) -> list[str]:
        mode = "【模拟】" if s.simulated else "【实盘】"
        elapsed = _elapsed(s.start_time)
        start_str = s.start_time.strftime("%m-%d %H:%M")

        cw = w - 3
        lw = cw // 2
        rw = cw - lw

        lines: list[str] = []
        hr = "─" * (w - 2)

        def row(text: str):
            visible = _strip_ansi(text)
            dw = _display_width(visible)
            if dw > cw:
                text = _truncate_to_width(text, cw)
                dw = _display_width(_strip_ansi(text))
            pad = cw - dw
            lines.append(f"│ {text}{' ' * pad}│")

        def row2(left: str, right: str):
            left_padded = _pad_right(left, lw)
            right_padded = _pad_right(right, rw)
            lines.append(f"│ {left_padded}{right_padded}│")

        # 标题
        lines.append(f"┌{hr}┐")
        title = " OKX 实盘交易 "
        left_dashes = (w - 2 - _display_width(title)) // 2
        right_dashes = w - 2 - left_dashes - _display_width(title)
        lines.append(f"│{'─' * left_dashes}{title}{'─' * right_dashes}│")

        row(f"策略: {s.strategy_name}  周期: {s.bar}  {mode}")
        row(f"启动: {start_str}    运行: {elapsed}")

        # 账户 + 风控
        lines.append(f"├{hr}┤")
        risk_status = red("暂停") if s.risk_halted else green("正常")
        acct_pnl = colored_pnl(s.account_pnl)
        acct_pct = colored_pnl_pct(s.account_pnl_pct)

        row2("账户", "风控")
        row2(f" 权益: {s.equity:.2f} USDT", f" 回撤: {s.drawdown_pct:.1f}%")
        row2(f" 可用: {s.available:.2f} USDT", f" 上限: {s.max_drawdown_pct:.1f}%")
        row2(f" 盈亏: {acct_pnl} ({acct_pct})", f" 持仓: {s.open_positions}/{s.max_positions}")
        row2("", f" 状态: {risk_status}")

        # 交易对表格
        lines.append(f"├{hr}┤")
        row(bold("交易对      现价      信号   状态       持仓      盈亏"))
        for ws in s.worker_states:
            if ws.get("error"):
                row(f" {ws['inst_id']:<10} -- 错误 --")
                continue

            inst = ws.get("inst_id", "")
            price = ws.get("last_price", 0)
            sig_name = ws.get("signal_name", "HOLD")
            sig = colored_signal(sig_name)
            pos = ws.get("position")
            coin = ws.get("position_coin", "")
            pnl_pct = ws.get("position_pnl_pct", 0)
            ind = ws.get("indicators", {})

            # 格式化价格（高价用整数，低价用小数）
            if price >= 100:
                price_str = f"${price:,.0f}"
            elif price >= 1:
                price_str = f"${price:,.2f}"
            else:
                price_str = f"${price:.4f}"

            if pos and pos.size > 0:
                size_str = f"{pos.size:.4g} {coin}"
                pnl_str = colored_pnl_pct(pnl_pct)
            else:
                size_str = "--"
                pnl_str = gray("--")

            # 状态列（regime）
            regime = ind.get("regime", "") if ind else ""
            regime_str = colored_regime(regime) if regime else gray("--")

            # 用固定列宽排版
            inst_col = _pad_right(f" {inst}", 12)
            price_col = _pad_right(price_str, 10)
            sig_col = _pad_right(sig, 7)
            regime_col = _pad_right(regime_str, 9)
            size_col = _pad_right(size_str, 10)
            row(f"{inst_col}{price_col}{sig_col}{regime_col}{size_col}{pnl_str}")

            # Adaptive 指标详情行
            if ind and "regime" in ind:
                adx_val = ind.get("adx", 0)
                bw_val = ind.get("bandwidth", 0)
                plus_di = ind.get("plus_di", 0)
                minus_di = ind.get("minus_di", 0)
                sub = ind.get("sub_strategy", "")
                detail = (f"   ↳ ADX={adx_val:.1f}  BW={bw_val:.1f}"
                          f"  +DI={plus_di:.1f}  -DI={minus_di:.1f}"
                          f"  子策略: {sub}")
                row(dim(detail))

        # 最近交易
        if s.recent_trades:
            lines.append(f"├{hr}┤")
            row(bold("最近交易"))
            for t in s.recent_trades[-5:]:
                side_str = colored_signal(t.side)
                pnl_str = f"  {t.pnl}" if t.pnl else ""
                row(f" {t.time}  {t.coin} {side_str}  ${t.price:.4f}  {t.size:.4g}{pnl_str}")

        # 底栏
        lines.append(f"├{hr}┤")
        row(f"轮次: #{s.tick_count}   更新: {s.last_update}")
        lines.append(f"└{hr}┘")

        return lines

    def _render_plain(self, state: MultiDashboardState):
        parts = []
        for ws in state.worker_states:
            inst = ws.get("inst_id", "?")
            price = ws.get("last_price", 0)
            sig = ws.get("signal_name", "HOLD")
            parts.append(f"{inst}=${price:.4f}({sig})")
        summary = "  ".join(parts)
        print(
            f"[#{state.tick_count}] {summary} "
            f"权益={state.equity:.2f} "
            f"回撤={state.drawdown_pct:.1f}%",
            flush=True,
        )


def _elapsed(start: datetime) -> str:
    delta = datetime.now() - start
    total_sec = int(delta.total_seconds())
    hours, remainder = divmod(total_sec, 3600)
    minutes, _ = divmod(remainder, 60)
    if hours > 0:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


def _pad_right(text: str, target_width: int) -> str:
    """将文本补齐到 target_width 显示宽度（兼容 CJK + ANSI），超宽时截断"""
    visible = _strip_ansi(text)
    current = _display_width(visible)
    if current > target_width:
        text = _truncate_to_width(text, target_width)
        visible = _strip_ansi(text)
        current = _display_width(visible)
    return text + " " * (target_width - current)


def _strip_ansi(s: str) -> str:
    """移除 ANSI 转义序列"""
    import re
    return re.sub(r"\033\[[0-9;]*m", "", s)


def _char_width(ch: str) -> int:
    """单个字符的显示宽度（CJK 字符占 2 列）"""
    cp = ord(ch)
    if (
        0x4E00 <= cp <= 0x9FFF      # CJK Unified
        or 0x3000 <= cp <= 0x303F    # CJK Symbols
        or 0xFF00 <= cp <= 0xFFEF    # Fullwidth
        or 0x3400 <= cp <= 0x4DBF    # CJK Extension A
        or 0x2E80 <= cp <= 0x2FFF    # CJK Radicals
    ):
        return 2
    return 1


def _display_width(s: str) -> int:
    """计算字符串显示宽度（CJK 字符占 2 列）"""
    return sum(_char_width(ch) for ch in s)


def _truncate_to_width(text: str, max_width: int) -> str:
    """将文本截断到 max_width 显示宽度（保留 ANSI 转义序列）"""
    import re
    ansi_re = re.compile(r'\033\[[0-9;]*m')
    width = 0
    result = []
    i = 0
    has_ansi = False
    while i < len(text):
        m = ansi_re.match(text, i)
        if m:
            result.append(m.group())
            i = m.end()
            has_ansi = True
            continue
        ch = text[i]
        cw = _char_width(ch)
        if width + cw > max_width:
            break
        result.append(ch)
        width += cw
        i += 1
    if has_ansi:
        result.append('\033[0m')
    return ''.join(result)
