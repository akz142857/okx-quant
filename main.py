#!/usr/bin/env python3
"""OKX 量化交易系统 — 主入口

用法:
    # 交互向导（无参数启动）
    python main.py

    # 回测模式
    python main.py backtest --inst BTC-USDT --strategy ma_cross --bar 4H --days 180

    # 实盘模式（需配置 API Key）
    python main.py live --inst BTC-USDT --strategy rsi_mean --bar 1H

    # 查看行情
    python main.py ticker --inst BTC-USDT

    # 查看可用交易对 / 策略
    python main.py list-pairs
    python main.py list-strategies
"""

import argparse
import logging
import os
import sys

logger = logging.getLogger(__name__)

from okx_quant.config import load_yaml
from okx_quant.strategy import STRATEGY_REGISTRY, is_llm_strategy

VALID_BARS = ["1m", "3m", "5m", "15m", "30m", "1H", "2H", "4H", "6H", "12H", "1D", "1W"]


def setup_logging(level: str = "INFO", log_file: str = ""):
    handlers = [logging.StreamHandler(sys.stdout)]
    if log_file:
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))

    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=handlers,
    )
    # 静默噪音日志
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("websockets").setLevel(logging.WARNING)


def load_config(path: str = "config.yaml") -> dict:
    if not os.path.exists(path):
        example = path.replace(".yaml", ".yaml.example")
        if os.path.exists(example):
            print(f"配置文件不存在，请复制 {example} 为 {path} 并填写 API Key")
        return {}
    return load_yaml(path)


def make_client(cfg: dict):
    from okx_quant.client.rest import OKXRestClient

    okx_cfg = cfg.get("okx", {})
    return OKXRestClient(
        api_key=okx_cfg.get("api_key", ""),
        secret_key=okx_cfg.get("secret_key", ""),
        passphrase=okx_cfg.get("passphrase", ""),
        simulated=okx_cfg.get("simulated", True),
        proxy=okx_cfg.get("proxy", ""),
    )


def make_strategy(name: str, params: dict | None = None, cfg: dict | None = None):
    entry = STRATEGY_REGISTRY.get(name)
    if not entry:
        print(f"未知策略: {name}，可选: {list(STRATEGY_REGISTRY.keys())}")
        sys.exit(1)
    cls = entry[0]

    from okx_quant.strategy import StrategyContext
    from okx_quant.strategy.multi_agent_strategy import MultiAgentStrategy

    # 多 Agent 策略：合并 config.yaml 的 multi_agent 配置到 params
    if issubclass(cls, MultiAgentStrategy) and cfg:
        ma_cfg = cfg.get("multi_agent", {})
        params = {**ma_cfg, **(params or {})}

    # 单 LLM 策略：注入 llm.max_total_tokens 预算
    if cfg and is_llm_strategy(name) and not issubclass(cls, MultiAgentStrategy):
        llm_cfg = cfg.get("llm", {})
        budget = llm_cfg.get("max_total_tokens")
        if budget is not None:
            params = {**(params or {}), "max_total_tokens": budget}

    # 构造 StrategyContext —— 所有外部依赖在构造时一次性注入
    context: StrategyContext | None = None
    if is_llm_strategy(name) and cfg:
        from okx_quant.llm import LLMClient, LLMConfig
        from okx_quant.data.news import CryptoNewsFetcher

        llm_cfg = cfg.get("llm", {})
        if not llm_cfg.get("api_key"):
            print("错误: LLM 策略需要配置 llm.api_key，请在 config.yaml 中填写")
            sys.exit(1)

        llm_client = LLMClient(LLMConfig.from_dict(llm_cfg))

        deep_client = None
        if issubclass(cls, MultiAgentStrategy):
            deep_cfg = cfg.get("llm_deep", {})
            if deep_cfg.get("api_key"):
                deep_client = LLMClient(LLMConfig.from_dict(deep_cfg))
            # 未配置 llm_deep：pipeline 自身会用 quick_llm 兜底

        news_cfg = cfg.get("news", {})
        news_fetcher = CryptoNewsFetcher(auth_token=news_cfg.get("auth_token", ""))

        context = StrategyContext(
            llm_client=llm_client,
            deep_llm_client=deep_client,
            news_fetcher=news_fetcher,
        )

    return cls(params, context=context) if context is not None else cls(params)


def _validate_bar(bar: str):
    if bar not in VALID_BARS:
        print(f"无效的 K 线周期: {bar}，可选: {', '.join(VALID_BARS)}")
        sys.exit(1)


def _validate_inst(inst: str):
    """校验交易对格式，支持逗号分隔的多个交易对"""
    for part in inst.split(","):
        part = part.strip()
        if "-" not in part:
            print(f"无效的交易对格式: {part}，应为 XXX-USDT 形式，如 BTC-USDT")
            sys.exit(1)


# -------------------------------------------------------------------------
# 子命令：行情查询
# -------------------------------------------------------------------------

def cmd_ticker(args, cfg):
    from okx_quant.data.market import MarketDataFetcher
    from tabulate import tabulate

    _validate_inst(args.inst)
    client = make_client(cfg)
    fetcher = MarketDataFetcher(client)

    ticker = fetcher.get_ticker(args.inst)
    spread = fetcher.get_spread(args.inst)

    print(f"\n=== {args.inst} 实时行情 ===")
    rows = [
        ["最新价", f"${ticker.get('last', 0):,.4f}"],
        ["买一价", f"${ticker.get('bid', 0):,.4f}"],
        ["卖一价", f"${ticker.get('ask', 0):,.4f}"],
        ["买卖价差", f"${spread.get('spread', 0):.6f} ({spread.get('spread_pct', 0):.4f}%)"],
        ["24H 涨跌", f"{ticker.get('change_24h_pct', 0):+.2f}%"],
        ["24H 最高", f"${ticker.get('high_24h', 0):,.4f}"],
        ["24H 最低", f"${ticker.get('low_24h', 0):,.4f}"],
        ["24H 成交量", f"{ticker.get('vol_24h', 0):,.2f}"],
    ]
    print(tabulate(rows, tablefmt="simple"))


# -------------------------------------------------------------------------
# 子命令：回测
# -------------------------------------------------------------------------

def cmd_backtest(args, cfg):
    from okx_quant.data.market import MarketDataFetcher
    from okx_quant.backtest import BacktestEngine, BacktestReport

    _validate_inst(args.inst)
    _validate_bar(args.bar)
    client = make_client(cfg)
    fetcher = MarketDataFetcher(client)

    backtest_cfg = cfg.get("backtest", {})
    initial_capital = backtest_cfg.get("initial_capital", 10000.0)
    fee_rate = backtest_cfg.get("fee_rate", 0.001)
    slippage = backtest_cfg.get("slippage", 0.0005)

    # 根据天数估算需要的 K 线数量
    bar_minutes = _bar_to_minutes(args.bar)
    total_bars = int(args.days * 24 * 60 / bar_minutes) + 50

    print(f"正在获取 {args.inst} {args.bar} K 线数据（约 {total_bars} 根）...")
    df = fetcher.get_history_candles(args.inst, bar=args.bar, total=total_bars)
    print(f"获取到 {len(df)} 根 K 线，时间范围: {df['ts'].iloc[0]} ~ {df['ts'].iloc[-1]}")

    strategy = make_strategy(args.strategy, cfg=cfg)

    # LLM 策略回测费用预估
    if is_llm_strategy(args.strategy):
        _confirm_llm_backtest(strategy, len(df))

    print(f"开始回测: 策略={strategy}  初始资金={initial_capital} USDT")

    engine = BacktestEngine(
        initial_capital=initial_capital,
        fee_rate=fee_rate,
        slippage=slippage,
    )
    result = engine.run(df, strategy, inst_id=args.inst)

    report = BacktestReport(result)
    report.print_summary()
    report.print_trades(max_rows=20)

    # LLM 用量统计
    if is_llm_strategy(args.strategy):
        _print_llm_usage(strategy)

    if args.export_csv:
        report.equity_to_csv(args.export_csv)


# -------------------------------------------------------------------------
# 子命令：实盘
# -------------------------------------------------------------------------

def cmd_screen(args, cfg):
    from okx_quant.data.screener import Screener, ScreenerConfig

    _validate_bar(args.bar)
    client = make_client(cfg)

    screener_cfg_raw = cfg.get("screener", {})
    screener_cfg = ScreenerConfig.from_dict(screener_cfg_raw)
    screener_cfg.bar = args.bar
    if hasattr(args, "min_vol") and args.min_vol is not None:
        screener_cfg.min_vol_24h_usdt = args.min_vol
    if hasattr(args, "max_price") and args.max_price:
        screener_cfg.max_price = args.max_price

    # 注入资金量过滤参数
    risk_cfg_raw = cfg.get("risk", {})
    screener_cfg.min_order_usdt = risk_cfg_raw.get("min_order_usdt", 5.0)
    try:
        from okx_quant.exchange import OKXExchange
        snap = OKXExchange(client).get_balance()
        screener_cfg.available_usdt = snap.available_quote
    except Exception as e:
        logger.warning("获取余额失败，跳过资金量过滤: %s", e)

    screener = Screener(client, screener_cfg)
    selected, scored_df = screener.run(top_n=args.top)
    screener.print_results(selected, scored_df)

    if selected:
        print(f"  推荐交易对: {', '.join(selected)}\n")


def _run_screen(cfg, top_n: int, bar: str, max_price: float = 0) -> list[str]:
    """选币并返回结果列表，供 cmd_live 调用"""
    from okx_quant.data.screener import Screener, ScreenerConfig

    client = make_client(cfg)
    screener_cfg_raw = cfg.get("screener", {})
    screener_cfg = ScreenerConfig.from_dict(screener_cfg_raw)
    screener_cfg.bar = bar
    screener_cfg.max_price = max_price

    # 注入资金量过滤参数
    risk_cfg_raw = cfg.get("risk", {})
    screener_cfg.min_order_usdt = risk_cfg_raw.get("min_order_usdt", 5.0)
    try:
        from okx_quant.exchange import OKXExchange
        snap = OKXExchange(client).get_balance()
        screener_cfg.available_usdt = snap.available_quote
    except Exception as e:
        logger.warning("获取余额失败，跳过资金量过滤: %s", e)

    screener = Screener(client, screener_cfg)
    selected, scored_df = screener.run(top_n=top_n)
    screener.print_results(selected, scored_df)
    return selected


def cmd_live(args, cfg):
    from okx_quant.trading.executor import LiveTrader
    from okx_quant.trading.state import StateStore
    from okx_quant.risk.manager import RiskConfig

    _validate_bar(args.bar)

    # 实盘二次确认：simulated=false 时需要用户显式确认
    # 自动化流水线可设置 OKX_LIVE_CONFIRMED=1 跳过交互（仅用于 CI，生产慎用）
    okx_cfg = cfg.get("okx")
    if not okx_cfg:
        # 配置缺失或 cfg 为空 → 无法判定模式，保险起见视作实盘并要求确认
        logger.warning("配置缺失 okx 段；保守视作实盘模式")
        simulated = False
    else:
        # 显式读取：只有明确写 true 才视为模拟盘，避免 None/缺失回退到 simulated
        simulated_raw = okx_cfg.get("simulated")
        simulated = bool(simulated_raw) if simulated_raw is not None else False

    if not simulated and not os.environ.get("OKX_LIVE_CONFIRMED"):
        print("\n" + "=" * 60)
        print("  ⚠️  警告：当前为【实盘模式】(simulated=false)")
        print("     程序将使用真实账户资金执行真实订单。")
        print("     建议先在 simulated=true 模拟盘充分测试策略。")
        print("     自动化场景可设置环境变量 OKX_LIVE_CONFIRMED=1 跳过确认。")
        print("=" * 60)
        confirm = input("  输入 'I UNDERSTAND' 以继续实盘交易: ").strip()
        if confirm != "I UNDERSTAND":
            print("已取消。如确需实盘请重试并输入完整确认语。")
            sys.exit(0)

    from okx_quant.exchange import OKXExchange
    from okx_quant.trading.position_restore import discover_positions

    client = make_client(cfg)
    exchange = OKXExchange(client)
    executor_cfg = cfg.get("executor", {})
    signal_timeout_s = float(executor_cfg.get("signal_timeout_s", 20))
    state_store = StateStore(state_dir=executor_cfg.get("state_dir", "state"))

    # 优先检测已有持仓（无论选币结果如何，已有持仓必须纳入监控）
    existing_positions: list[str] = []
    for inst_id, balance in discover_positions(exchange, exchange.quote_ccy):
        existing_positions.append(inst_id)
        ccy = inst_id.split("-")[0]
        print(f"  检测到已有持仓: {inst_id}（{balance} {ccy}）")

    # 自动选币
    screen_n = getattr(args, "screen", 0) or 0
    if screen_n > 0:
        max_price = getattr(args, "max_price", 0) or 0
        selected = _run_screen(cfg, top_n=screen_n, bar=args.bar, max_price=max_price)
        # 合并已有持仓（选币结果可以为空，只要有持仓就能继续）
        for pos_inst in existing_positions:
            if pos_inst not in selected:
                selected.append(pos_inst)
        if not selected:
            print("选币结果为空且无已有持仓，退出")
            sys.exit(1)
        print(f"  最终交易列表: {', '.join(selected)}")
        # systemd / CI 等非交互场景：stdin 不是 tty，或显式 --yes，跳过确认
        auto = getattr(args, "yes", False) or not sys.stdin.isatty()
        if auto:
            print("  [auto-confirm] 非交互环境，自动确认以上交易对")
        else:
            confirm = input("  确认使用以上交易对开始交易? (y/N): ").strip().lower()
            if confirm != "y":
                print("已取消")
                sys.exit(0)
        args.inst = ",".join(selected)

    if args.inst:
        _validate_inst(args.inst)

    # 构建最终交易对列表，确保已有持仓始终包含在内
    instruments = [s.strip() for s in args.inst.split(",")] if args.inst else []
    for pos_inst in existing_positions:
        if pos_inst not in instruments:
            instruments.append(pos_inst)
            print(f"  已有持仓 {pos_inst} 自动加入交易列表")

    if not instruments:
        print("错误: 无交易对可监控")
        sys.exit(1)

    risk_cfg_raw = cfg.get("risk", {})
    risk_config = RiskConfig(
        max_position_pct=risk_cfg_raw.get("max_position_pct", 0.1),
        stop_loss_pct=risk_cfg_raw.get("stop_loss_pct", 0.02),
        take_profit_pct=risk_cfg_raw.get("take_profit_pct", 0.04),
        max_drawdown_pct=risk_cfg_raw.get("max_drawdown_pct", 0.15),
        max_open_positions=risk_cfg_raw.get("max_open_positions", 1),
        min_order_usdt=risk_cfg_raw.get("min_order_usdt", 5.0),
        drawdown_recover_ratio=risk_cfg_raw.get("drawdown_recover_ratio", 0.5),
    )

    use_dashboard = not args.no_dashboard

    # 多币种 → Supervisor
    if len(instruments) > 1:
        from okx_quant.trading.supervisor import Supervisor

        strategy_factory = lambda: make_strategy(args.strategy, cfg=cfg)

        if not use_dashboard:
            mode = "【模拟盘】" if simulated else "【实盘】"
            print(f"\n启动 {mode} 多币种实盘交易")
            print(f"交易对: {', '.join(instruments)}  策略: {args.strategy}  K 线周期: {args.bar}")
            print(f"风控: 最大仓位={risk_config.max_position_pct*100:.0f}%  止损={risk_config.stop_loss_pct*100:.1f}%")
            print("按 Ctrl+C 停止\n")

        supervisor = Supervisor(
            exchange=exchange,
            instruments=instruments,
            strategy_factory=strategy_factory,
            risk_config=risk_config,
            bar=args.bar,
            lookback=100,
            interval_seconds=args.interval,
            dashboard=use_dashboard,
            simulated=simulated,
            signal_timeout_s=signal_timeout_s,
            state_store=state_store,
        )
        supervisor.run()
        return

    # 单币种 → 现有 LiveTrader 逻辑（向后兼容）
    strategy = make_strategy(args.strategy, cfg=cfg)

    if not use_dashboard:
        mode = "【模拟盘】" if simulated else "【实盘】"
        print(f"\n启动 {mode} 实盘交易")
        print(f"交易对: {args.inst}  策略: {args.strategy}  K 线周期: {args.bar}")
        print(f"风控: 最大仓位={risk_config.max_position_pct*100:.0f}%  止损={risk_config.stop_loss_pct*100:.1f}%")
        print("按 Ctrl+C 停止\n")

    trader = LiveTrader(
        exchange=exchange,
        strategy=strategy,
        inst_id=instruments[0],
        risk_config=risk_config,
        dashboard=use_dashboard, simulated=simulated,
        signal_timeout_s=signal_timeout_s,
        state_store=state_store,
    )
    trader.run(bar=args.bar, lookback=100, interval_seconds=args.interval)


# -------------------------------------------------------------------------
# 子命令：查看可用交易对
# -------------------------------------------------------------------------

def cmd_list_pairs(args, cfg):
    from okx_quant.data.market import MarketDataFetcher
    from tabulate import tabulate

    client = make_client(cfg)
    fetcher = MarketDataFetcher(client)

    tickers = fetcher.get_all_tickers()
    if tickers.empty:
        print("无法获取交易对列表")
        return

    # 按成交量排序，显示 USDT 交易对
    usdt_pairs = tickers[tickers["inst_id"].str.endswith("-USDT")].copy()
    usdt_pairs = usdt_pairs.sort_values("vol_24h", ascending=False)

    print(f"\n可用 USDT 现货交易对（共 {len(usdt_pairs)} 个，按 24H 成交量排序）:\n")
    rows = []
    for _, r in usdt_pairs.head(30).iterrows():
        change = r["change_24h_pct"]
        change_str = f"{change:+.2f}%" if change else "N/A"
        rows.append([r["inst_id"], f"${r['last']:,.4f}", change_str, f"{r['vol_24h']:,.0f}"])

    print(tabulate(rows, headers=["交易对", "最新价", "24H涨跌", "24H成交量"], tablefmt="simple"))
    if len(usdt_pairs) > 30:
        print(f"\n... 共 {len(usdt_pairs)} 个交易对，仅显示前 30 个")


# -------------------------------------------------------------------------
# 子命令：查看可用策略
# -------------------------------------------------------------------------

def cmd_list_strategies(args, cfg):
    from okx_quant.cli.colors import bold, cyan, dim, yellow

    print(cyan("\n可用策略:\n"))
    for key, (cls, cn_name, desc) in STRATEGY_REGISTRY.items():
        tag = f" {yellow('[AI]')}" if is_llm_strategy(key) else ""
        print(f"  {bold(key):<20} {cn_name}{tag}")
        print(f"  {'':20} {dim(desc)}\n")


# -------------------------------------------------------------------------
# LLM 策略辅助
# -------------------------------------------------------------------------

# 每 1K token 的近似成本（USD），用于回测费用预估
_LLM_COST_PER_1K: dict[str, tuple[float, float]] = {
    # (input_cost, output_cost) per 1K tokens
    "gpt-4o-mini": (0.00015, 0.0006),
    "gpt-4o": (0.0025, 0.01),
    "claude-sonnet-4-6": (0.003, 0.015),
    "claude-opus-4-6": (0.015, 0.075),
    "claude-haiku-4-5-20251001": (0.0008, 0.004),
    "deepseek-chat": (0.00014, 0.00028),
}


def _estimate_cost(model: str, input_tokens: int, output_tokens: int) -> float:
    """根据模型和 token 数量估算费用（USD）"""
    costs = _LLM_COST_PER_1K.get(model, (0.001, 0.002))
    return (input_tokens / 1000 * costs[0]) + (output_tokens / 1000 * costs[1])


def _confirm_llm_backtest(strategy, num_bars: int):
    """LLM 回测前打印费用预估并要求确认"""
    from okx_quant.strategy.ensemble import EnsembleStrategy
    from okx_quant.strategy.multi_agent_strategy import MultiAgentStrategy

    model = strategy.llm_model
    is_ensemble = isinstance(strategy, EnsembleStrategy)
    is_multi_agent = isinstance(strategy, MultiAgentStrategy)

    print(f"\n{'='*50}")
    print(f"  LLM 回测费用预估")
    print(f"  模型: {model}")

    if is_multi_agent:
        # 多 Agent: 每根 K 线 ~10 次调用（4 分析师 + 4 辩论 + 1 交易员 + 1 风控）
        # 分析师(cheap): ~800 in + ~300 out 每次 × 4 = ~3200 in + ~1200 out
        # 辩论+决策(deep): ~2000 in + ~500 out 每次 × 6 = ~12000 in + ~3000 out
        calls_per_bar = 10
        cheap_in = num_bars * 3200
        cheap_out = num_bars * 1200
        deep_in = num_bars * 12000
        deep_out = num_bars * 3000
        # 从复合模型字符串中拆出两个模型
        models = [m.strip() for m in model.split("+")]
        cheap_model = models[0] if models else "deepseek-chat"
        deep_model = models[1] if len(models) > 1 else cheap_model
        est_cost = (_estimate_cost(cheap_model, cheap_in, cheap_out)
                    + _estimate_cost(deep_model, deep_in, deep_out))
        total_tokens = cheap_in + cheap_out + deep_in + deep_out

        print(f"  最大调用次数: ~{num_bars * calls_per_bar} 次 ({calls_per_bar}/bar)")
        print(f"  预估 Token 上限: ~{total_tokens:,}")
        print(f"    分析师({cheap_model}): ~{cheap_in + cheap_out:,}")
        print(f"    辩论+决策({deep_model}): ~{deep_in + deep_out:,}")
        print(f"  预估费用上限: ~${est_cost:.4f} USD")
    else:
        # 单 LLM 策略：每根 K 线 ~1 次调用
        est_input_tokens = num_bars * 1200
        est_output_tokens = num_bars * 150
        est_cost = _estimate_cost(model, est_input_tokens, est_output_tokens)

        print(f"  最大调用次数: ~{num_bars} 次")
        print(f"  预估 Token 上限: ~{est_input_tokens + est_output_tokens:,} ({est_input_tokens:,} in + {est_output_tokens:,} out)")
        print(f"  预估费用上限: ~${est_cost:.4f} USD")

    if is_ensemble:
        print(f"  注: 集成策略仅在传统策略达成共识时调用 LLM，实际费用通常远低于预估")
    print(f"{'='*50}")

    confirm = input("\n  确认运行 LLM 回测? (y/N): ").strip().lower()
    if confirm != "y":
        print("已取消")
        sys.exit(0)


def _print_llm_usage(strategy):
    """回测结束后打印 LLM 用量统计"""
    from okx_quant.strategy.multi_agent_strategy import MultiAgentStrategy

    usage = strategy.get_usage_summary()
    model = strategy.llm_model

    print(f"\n{'='*50}")
    print(f"  LLM 用量统计")
    print(f"  模型: {model}")
    print(f"  总调用次数: {usage['total_calls']}")
    print(f"  总 Token: {usage['total_tokens']:,} ({usage['total_input_tokens']:,} in + {usage['total_output_tokens']:,} out)")

    # 多 Agent 策略：按 agent 分拆费用估算
    if isinstance(strategy, MultiAgentStrategy) and "per_agent" in usage:
        models = [m.strip() for m in model.split("+")]
        cheap_model = models[0] if models else ""
        deep_model = models[1] if len(models) > 1 else cheap_model
        cheap_agents = {"technical", "sentiment", "news", "fundamentals"}

        total_cost = 0.0
        for agent_name, agent_usage in usage["per_agent"].items():
            m = cheap_model if agent_name in cheap_agents else deep_model
            cost = _estimate_cost(m, agent_usage["input_tokens"], agent_usage["output_tokens"])
            total_cost += cost
        print(f"  预估实际费用: ~${total_cost:.4f} USD")
    else:
        actual_cost = _estimate_cost(model, usage["total_input_tokens"], usage["total_output_tokens"])
        print(f"  预估实际费用: ~${actual_cost:.4f} USD")

    print(f"{'='*50}")


# -------------------------------------------------------------------------
# 工具函数
# -------------------------------------------------------------------------

def _bar_to_minutes(bar: str) -> int:
    mapping = {
        "1m": 1, "3m": 3, "5m": 5, "15m": 15, "30m": 30,
        "1H": 60, "2H": 120, "4H": 240, "6H": 360, "12H": 720,
        "1D": 1440, "1W": 10080,
    }
    return mapping.get(bar, 60)


# -------------------------------------------------------------------------
# CLI 入口
# -------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        prog="okx-quant",
        description="OKX 数字货币量化交易系统",
    )
    parser.add_argument("--config", default="config.yaml", help="配置文件路径")
    parser.add_argument("--log-level", default="INFO", help="日志级别")
    subparsers = parser.add_subparsers(dest="command")

    strategy_choices = list(STRATEGY_REGISTRY.keys())

    # ticker
    p_ticker = subparsers.add_parser("ticker", help="查看实时行情")
    p_ticker.add_argument("--inst", required=True, help="交易对，如 BTC-USDT")

    # backtest
    p_bt = subparsers.add_parser("backtest", help="策略回测")
    p_bt.add_argument("--inst", required=True, help="交易对，如 BTC-USDT")
    p_bt.add_argument("--strategy", default="ma_cross", choices=strategy_choices)
    p_bt.add_argument("--bar", default="4H", help="K 线周期，如 1H/4H/1D")
    p_bt.add_argument("--days", type=int, default=180, help="回测天数")
    p_bt.add_argument("--export-csv", default="", help="导出权益曲线到 CSV 文件")

    # live
    p_live = subparsers.add_parser("live", help="实盘/模拟盘交易")
    p_live.add_argument("--inst", default="", help="交易对，多个用逗号分隔，如 DOGE-USDT,BTC-USDT")
    p_live.add_argument("--strategy", default="ma_cross", choices=strategy_choices)
    p_live.add_argument("--bar", default="1H", help="K 线周期")
    p_live.add_argument("--interval", type=int, default=60, help="轮询间隔（秒）")
    p_live.add_argument("--no-dashboard", action="store_true", help="禁用面板，使用日志输出")
    p_live.add_argument("--screen", type=int, default=0, help="自动选币数量，如 --screen 5")
    p_live.add_argument("--max-price", type=float, default=0, help="选币最大单价过滤 (USDT，0=不过滤)")
    p_live.add_argument("-y", "--yes", action="store_true", help="跳过交易对确认 prompt（自动化必用）")

    # screen
    p_screen = subparsers.add_parser("screen", help="因子选币器")
    p_screen.add_argument("--top", type=int, default=5, help="选出 top N 交易对")
    p_screen.add_argument("--bar", default="4H", help="K 线周期")
    p_screen.add_argument("--min-vol", type=float, default=None, help="最小 24H 成交额 (USDT)")
    p_screen.add_argument("--max-price", type=float, default=0, help="最大单价过滤 (USDT，0=不过滤)")

    # list-pairs
    subparsers.add_parser("list-pairs", help="查看可用交易对")

    # list-strategies
    subparsers.add_parser("list-strategies", help="查看可用策略")

    args = parser.parse_args()

    # 无子命令时进入交互向导
    if args.command is None:
        from okx_quant.cli.wizard import run_wizard
        command, params = run_wizard()
        args.command = command
        for k, v in params.items():
            setattr(args, k, v)

    cfg = load_config(args.config)
    log_cfg = cfg.get("logging", {})
    setup_logging(args.log_level, log_cfg.get("file", ""))

    if args.command == "ticker":
        cmd_ticker(args, cfg)
    elif args.command == "backtest":
        cmd_backtest(args, cfg)
    elif args.command == "live":
        # --inst 或 --screen 至少指定一个
        screen_n = getattr(args, "screen", 0) or 0
        if not args.inst and screen_n <= 0:
            print("错误: 实盘模式需要指定 --inst 或 --screen")
            sys.exit(1)
        cmd_live(args, cfg)
    elif args.command == "screen":
        cmd_screen(args, cfg)
    elif args.command == "list-pairs":
        cmd_list_pairs(args, cfg)
    elif args.command == "list-strategies":
        cmd_list_strategies(args, cfg)


if __name__ == "__main__":
    main()
