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
import atexit
import grp
import json
import logging
import os
import pwd
import sys
import tempfile
import time
from decimal import Decimal
from pathlib import Path

from okx_quant.config import load_yaml
from okx_quant.strategy import STRATEGY_REGISTRY, is_llm_strategy

logger = logging.getLogger(__name__)

VALID_BARS = ["1m", "3m", "5m", "15m", "30m", "1H", "2H", "4H", "6H", "12H", "1D", "1W"]


def setup_logging(
    level: str = "INFO",
    log_file: str = "",
    *,
    structured: bool = False,
    secrets: list[str] | None = None,
):
    handlers = [logging.StreamHandler(sys.stdout)]
    if log_file:
        log_directory = os.path.dirname(log_file)
        if log_directory:
            os.makedirs(log_directory, exist_ok=True)
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))

    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=handlers,
        force=True,
    )
    if structured:
        from okx_quant.infrastructure.logging import (
            JsonFormatter,
            SecretRedactionFilter,
        )

        formatter = JsonFormatter()
        redaction = SecretRedactionFilter(secrets or [])
        for handler in handlers:
            handler.setFormatter(formatter)
            handler.addFilter(redaction)
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


def load_env_file(path: str) -> None:
    """安全读取 systemd 风格 KEY=VALUE，不执行 shell 语法。"""
    if not path:
        return
    with open(path, encoding="utf-8") as handle:
        for line_number, raw in enumerate(handle, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                raise ValueError(f"环境文件第 {line_number} 行缺少 '='")
            key, value = line.split("=", 1)
            key = key.strip()
            if not key or not key.replace("_", "").isalnum() or not key[0].isalpha():
                raise ValueError(f"环境文件第 {line_number} 行变量名非法")
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
                value = value[1:-1]
            os.environ.setdefault(key, value)


def make_client(cfg: dict):
    from okx_quant.client.rest import OKXRestClient

    okx_cfg = cfg.get("okx", {})
    return OKXRestClient(
        api_key=okx_cfg.get("api_key", ""),
        secret_key=okx_cfg.get("secret_key", ""),
        passphrase=okx_cfg.get("passphrase", ""),
        simulated=okx_cfg.get("simulated", True),
        proxy=okx_cfg.get("proxy", ""),
        base_url=okx_cfg.get("base_url", ""),
        ca_bundle=okx_cfg.get("ca_bundle", ""),
        timeout=int(okx_cfg.get("timeout", 15)),
        max_retries=int(okx_cfg.get("max_retries", 3)),
    )


def make_strategy(name: str, params: dict | None = None, cfg: dict | None = None):
    entry = STRATEGY_REGISTRY.get(name)
    if not entry:
        print(f"未知策略: {name}，可选: {list(STRATEGY_REGISTRY.keys())}")
        sys.exit(1)
    cls = entry[0]

    from okx_quant.strategy import StrategyContext
    from okx_quant.strategy.multi_agent_strategy import MultiAgentStrategy

    # 从 config.yaml 的 strategies.<name> 读取自定义参数（Phase 2 用）
    # 例如：strategies: { ma_cross: { fast_period: 5, slow_period: 13 } }
    if cfg:
        strategies_cfg = cfg.get("strategies") or {}
        strat_params = strategies_cfg.get(name) or {}
        if strat_params:
            params = {**strat_params, **(params or {})}

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
        from okx_quant.data.news import CryptoNewsFetcher
        from okx_quant.llm import LLMClient, LLMConfig

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


DEFAULT_SIGNAL_TIMEOUT_S = 20.0


def _resolve_signal_timeout(cfg: dict, executor_cfg: dict, strategy_name: str) -> float:
    """解析 generate_signal 的硬超时预算

    默认 20s 对传统策略（纯 pandas 计算）是合适的保护，但对 LLM 策略低了一个
    数量级：multi_agent 一次决策要串起 4 个分析师 + N 轮辩论 + 交易员 + 风控，
    典型 35–70s。而 ``utils.run_with_timeout`` 的守护线程**无法被杀死**——超时
    只是主循环先返回 HOLD，后台仍会把全部 LLM 调用跑完并计费。也就是说超时值
    配小了不省钱，只是让每一次决策都变成"付了全款拿 HOLD"。

    因此：LLM 类策略在**未显式配置** ``executor.signal_timeout_s`` 时，按各阶段
    超时上限推导一个匹配的预算；显式配置则一律尊重用户设置。
    """
    explicit = executor_cfg.get("signal_timeout_s")
    if explicit is not None:
        return float(explicit)
    if not is_llm_strategy(strategy_name):
        return DEFAULT_SIGNAL_TIMEOUT_S

    llm_timeout = float(cfg.get("llm", {}).get("timeout", 30))
    deep_timeout = float(cfg.get("llm_deep", {}).get("timeout", 60) or llm_timeout)
    debate_rounds = int(cfg.get("multi_agent", {}).get("debate_rounds", 2))
    # 分析师阶段（并行，取单个上限）+ 每轮辩论（轮内并行）+ 交易员 + 风控
    derived = llm_timeout + (debate_rounds + 2) * deep_timeout
    timeout = max(DEFAULT_SIGNAL_TIMEOUT_S, derived)
    print(
        f"  [signal_timeout] 策略 {strategy_name} 为 LLM 类，未显式配置 "
        f"executor.signal_timeout_s，按各阶段超时上限推导为 {timeout:.0f}s"
        f"（默认 {DEFAULT_SIGNAL_TIMEOUT_S:.0f}s 会让每次决策都超时降级为 HOLD，"
        f"但后台调用仍会跑完并计费）"
    )
    return timeout


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
    from tabulate import tabulate

    from okx_quant.data.market import MarketDataFetcher

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
    from okx_quant.backtest import BacktestEngine, BacktestReport
    from okx_quant.data.market import MarketDataFetcher

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


def _validate_production_deployment(
    args,
    cfg,
    settings,
) -> dict | None:
    """Ultimate in-process guard; direct console invocation cannot bypass it."""
    release_root = Path(settings.release_root)
    if not release_root.is_dir():
        raise ValueError("生产 release_root 不存在")
    release_root_text = str(release_root)
    if release_root_text not in sys.path:
        sys.path.insert(0, release_root_text)
    from scripts.deployment_receipt import validate_deployment_receipt
    from scripts.launch_manifest import load_launch_manifest
    from scripts.production_gate import _actual_runtime_identity

    launch = load_launch_manifest(Path(settings.launch_manifest_path))
    requested_instruments = [item.strip() for item in args.inst.split(",") if item.strip()]
    if (
        getattr(args, "screen", 0)
        or args.strategy != launch["strategy"]
        or args.bar != launch["bar"]
        or requested_instruments != launch["instruments"]
        or args.interval != launch["interval_seconds"]
    ):
        raise ValueError("实际 live argv 未精确匹配 root-owned launch manifest")
    identity = _actual_runtime_identity(
        config_path=Path(args.config),
        release_commit_file=release_root / "REVISION",
        strategy=launch["strategy"],
        bar=launch["bar"],
        instruments=launch["instruments"],
        interval=float(launch["interval_seconds"]),
    )
    receipt = validate_deployment_receipt(
        Path(settings.deployment_receipt_path),
        identity=identity,
        approval_path=Path(settings.admission_approval_path),
        approval_public_key=Path(settings.admission_approval_public_key),
        evidence_path=Path(settings.admission_evidence_path),
    )
    if getattr(settings, "deployment_tier", "production") == "canary":
        from okx_quant.research.canary import (
            identity_sha256,
            validate_canary_runtime,
        )

        transition, policy = validate_canary_runtime(
            settings=settings,
            config=cfg,
            actual_runtime_identity=identity,
            deployment_receipt=receipt,
        )
        return {
            "expires_at": policy["expires_at"],
            "backup_rpo_seconds": policy["auto_halt"]["backup_rpo_seconds"],
            "transition_sha256": identity_sha256(transition),
            "policy_sha256": identity_sha256(policy),
            "target_sha256": identity_sha256(transition["target_deployment_identity"]),
            "demo_soak_epoch_id": transition["demo_soak_epoch_id"],
            "source_key_fingerprints": transition["post_start_source_key_fingerprints"],
            "source_producer_inventory": transition[
                "source_producer_inventory"
            ],
            "target_key_fingerprint": transition[
                "target_deployment_identity"
            ]["key_fingerprint"],
        }
    return None


def _validate_demo_deployment(
    args,
    cfg,
    settings,
    *,
    process_argv: list[str] | None = None,
    proc_root: Path = Path("/proc"),
    current_uid: int | None = None,
    now: int | None = None,
) -> dict:
    """Fail closed inside the trader before constructing an OKX client."""
    from okx_quant.ops.demo_preflight import (
        DemoDeploymentProfile,
        validate_demo_process_receipt,
        validate_runtime_profile_binding,
    )

    profile = DemoDeploymentProfile.from_config(cfg)
    validate_runtime_profile_binding(profile, settings, cfg)
    if tuple(
        item.strip() for item in str(args.inst).split(",") if item.strip()
    ) != (profile.instrument,):
        raise RuntimeError("Demo runtime/config/profile identity 不一致")
    return validate_demo_process_receipt(
        cfg=cfg,
        profile=profile,
        config_path=Path(args.config),
        process_argv=list(sys.argv if process_argv is None else process_argv),
        proc_root=proc_root,
        current_uid=current_uid,
        now=now,
    )


def _strategy_instruments(
    requested: list[str],
    existing_positions: list[str],
    *,
    production: bool,
) -> list[str]:
    instruments = list(requested)
    if production:
        return instruments
    for inst_id in existing_positions:
        if inst_id not in instruments:
            instruments.append(inst_id)
    return instruments


def cmd_live(args, cfg):
    from okx_quant.config import ProductionSettings
    from okx_quant.domain.orders import SystemMode
    from okx_quant.risk.manager import RiskConfig
    from okx_quant.trading.executor import LiveTrader
    from okx_quant.trading.state import StateStore

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

    # 仅当显式等于 "1" 才跳过确认；"0"/"false"/任意其它值都要求交互确认，
    # 避免"我把它设成 0 来关闭"反而开启实盘的反直觉陷阱。
    if not simulated and os.environ.get("OKX_LIVE_CONFIRMED") != "1":
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

    production_cfg = ProductionSettings.from_config(cfg)
    launch_authorized = True
    launch_error = ""
    entry_authorization_expires_at = 0.0
    entry_backup_rpo_seconds = 0.0
    canary_runtime_binding: dict = {}
    if production_cfg.environment == "production":
        try:
            entry_authorization = _validate_production_deployment(
                args,
                cfg,
                production_cfg,
            )
            if entry_authorization is not None:
                canary_runtime_binding = entry_authorization
                entry_authorization_expires_at = float(entry_authorization["expires_at"])
                entry_backup_rpo_seconds = float(entry_authorization["backup_rpo_seconds"])
        except Exception as exc:  # safety kernel must still start fail-closed
            launch_authorized = False
            launch_error = f"{type(exc).__name__}: {exc}"
            logger.critical(
                "生产部署准入无效；仅启动 HALTED safety kernel: %s",
                launch_error,
            )
    elif production_cfg.environment == "demo":
        try:
            _validate_demo_deployment(args, cfg, production_cfg)
        except Exception as exc:
            logger.critical(
                "Demo 进程内部署准入无效；在创建 OKX client 前拒绝启动: %s: %s",
                type(exc).__name__,
                exc,
            )
            raise SystemExit(1) from exc
    if getattr(args, "safety_only", False):
        launch_authorized = False
        launch_error = launch_error or "wrapper requested safety-only mode"

    from okx_quant.exchange import OKXExchange
    from okx_quant.trading.position_restore import discover_positions

    client = make_client(cfg)
    exchange = OKXExchange(client)
    production_runtime = None
    strategy_revision = ""
    if production_cfg.enabled:
        from okx_quant.application.approval import production_config_hash
        from okx_quant.application.risk_service import ProductionRiskLimits
        from okx_quant.application.runtime import ProductionRuntime
        from okx_quant.client.websocket import OKXWebSocketClient
        from okx_quant.infrastructure.db import SQLiteJournal

        journal = SQLiteJournal(
            production_cfg.journal_path,
            must_exist=(
                production_cfg.environment == "production" or bool(production_cfg.account_id)
            ),
        )
        revision_path = Path(production_cfg.release_root) / "REVISION"
        if (
            launch_authorized
            and production_cfg.account_id
            and revision_path.is_file()
            and not revision_path.is_symlink()
        ):
            strategy_revision = revision_path.read_text(encoding="ascii").strip().lower()
        if production_cfg.account_id:
            journal.assert_identity(production_cfg.account_id)
        if (
            production_cfg.environment == "production"
            and not launch_authorized
            and journal.get_mode()
            not in {
                SystemMode.HALTED,
                SystemMode.EMERGENCY_EXIT,
                SystemMode.MAINTENANCE,
            }
        ):
            journal.set_mode(SystemMode.HALTED)
        runtime_config_hash = production_config_hash(production_cfg, cfg)
        risk_limits = ProductionRiskLimits(
            max_order_loss_usdt=production_cfg.max_order_loss_usdt,
            max_position_notional_usdt=production_cfg.max_position_notional_usdt,
            max_total_exposure_usdt=production_cfg.max_total_exposure_usdt,
            max_open_positions=production_cfg.max_open_positions,
            max_daily_loss_usdt=production_cfg.max_daily_loss_usdt,
            max_drawdown_ratio=production_cfg.max_drawdown_ratio,
            max_order_intents_per_hour=production_cfg.max_order_intents_per_hour,
            max_spread_ratio=production_cfg.max_spread_ratio,
            max_slippage_ratio=production_cfg.max_slippage_ratio,
            max_candle_range_ratio=(production_cfg.max_candle_range_ratio),
            min_24h_quote_volume_usdt=(production_cfg.min_24h_quote_volume_usdt),
            max_market_data_age_s=production_cfg.max_market_data_age_s,
            max_account_snapshot_age_s=production_cfg.max_account_snapshot_age_s,
            allowed_instruments=frozenset(production_cfg.allowed_instruments),
        )
        connection_targets = None
        demo_profile = None
        if production_cfg.environment == "demo" and "demo_validation" in cfg:
            from okx_quant.ops.demo_preflight import DemoDeploymentProfile

            demo_profile = DemoDeploymentProfile.from_config(cfg)
            connection_targets = demo_profile.websocket_targets()
        account_lease = None
        if demo_profile is not None and demo_profile.external_lease_public_key is not None:
            from okx_quant.ops.account_lease import SignedAccountLeaseClient

            account_lease = SignedAccountLeaseClient(
                base_url=demo_profile.external_lease_url,
                public_key=demo_profile.external_lease_public_key,
                token_env=demo_profile.external_lease_token_env,
                account_uid=demo_profile.account_uid,
                broker_id=demo_profile.external_lease_broker_id,
                ttl_s=demo_profile.external_lease_ttl_s,
            )
        ws = OKXWebSocketClient(
            api_key=okx_cfg.get("api_key", ""),
            secret_key=okx_cfg.get("secret_key", ""),
            passphrase=okx_cfg.get("passphrase", ""),
            simulated=simulated,
            connection_targets=connection_targets,
        )
        production_runtime = ProductionRuntime(
            exchange,
            journal,
            risk_limits=risk_limits,
            websocket=ws,
            lock_path=production_cfg.lock_path,
            reconciliation_interval_s=production_cfg.reconciliation_interval_s,
            max_clock_skew_s=production_cfg.max_clock_skew_s,
            ws_ready_timeout_s=production_cfg.ws_ready_timeout_s,
            max_unprotected_position_s=(production_cfg.max_unprotected_position_s),
            max_consecutive_infrastructure_errors=(
                production_cfg.max_consecutive_infrastructure_errors
            ),
            shadow_mode=production_cfg.shadow_mode,
            safety_only=not launch_authorized,
            heartbeat_path=production_cfg.heartbeat_path,
            backup_dir=(
                "" if production_cfg.external_backup_managed else production_cfg.backup_dir
            ),
            backup_interval_s=production_cfg.backup_interval_s,
            backup_retention_days=production_cfg.backup_retention_days,
            offsite_backup_uri=production_cfg.offsite_backup_uri,
            alert_webhook_url=os.environ.get(production_cfg.alert_webhook_env, ""),
            metrics_host=production_cfg.metrics_host,
            metrics_port=production_cfg.metrics_port,
            expected_account_id=production_cfg.account_id,
            deployment_unit=(
                demo_profile.unit_name
                if demo_profile is not None
                else production_cfg.deployment_unit
            ),
            soak_epoch_id=(
                demo_profile.soak_epoch_id
                if demo_profile is not None
                else canary_runtime_binding.get("demo_soak_epoch_id", "")
            ),
            approval_public_key=production_cfg.resume_approval_public_key,
            production_config_hash=runtime_config_hash,
            environment=production_cfg.environment,
            allowed_instruments=production_cfg.allowed_instruments,
            resource_sample_interval_s=(production_cfg.resource_sample_interval_s),
            memory_high_bytes=production_cfg.memory_high_bytes,
            memory_max_bytes=production_cfg.memory_max_bytes,
            limit_nofile=production_cfg.limit_nofile,
            tasks_max=production_cfg.tasks_max,
            max_database_bytes=production_cfg.max_database_bytes,
            max_wal_bytes=production_cfg.max_wal_bytes,
            max_wal_checkpoint_age_s=(
                production_cfg.max_wal_checkpoint_age_s
            ),
            max_database_growth_bytes_per_day=(production_cfg.max_database_growth_bytes_per_day),
            resource_min_free_bytes=production_cfg.resource_min_free_bytes,
            resource_min_free_inodes=(production_cfg.resource_min_free_inodes),
            release_identity=strategy_revision,
            entry_authorization_expires_at=(entry_authorization_expires_at),
            max_entry_backup_rpo_s=entry_backup_rpo_seconds,
            expected_model_slippage_ratio=float(cfg.get("backtest", {}).get("slippage", 0)),
            cost_model_manifest=(
                demo_profile.cost_model_manifest if demo_profile is not None else None
            ),
            demo_probe_schedule_path=(
                demo_profile.probe_schedule_path
                if demo_profile is not None and demo_profile.probe_schedule_path is not None
                else ""
            ),
            require_formal_demo_probe_schedule=(
                demo_profile is not None and demo_profile.role == "active"
            ),
            demo_probe_only=(demo_profile is not None and demo_profile.role == "active"),
            backup_receipt_path=(
                demo_profile.backup_receipt_path
                if demo_profile is not None
                else (
                    production_cfg.backup_receipt_path
                    if production_cfg.environment == "production"
                    else ""
                )
            ),
            backup_receipt_public_key=(
                demo_profile.backup_receipt_public_key
                if demo_profile is not None
                else (
                    production_cfg.backup_receipt_public_key
                    if production_cfg.environment == "production"
                    else ""
                )
            ),
            backup_receipt_key_id=(
                demo_profile.backup_receipt_key_id
                if demo_profile is not None
                else (
                    production_cfg.backup_receipt_key_id
                    if production_cfg.environment == "production"
                    else ""
                )
            ),
            external_control_inbox_dir=(
                demo_profile.operator_inbox_dir if demo_profile is not None else ""
            ),
            alert_provider_receipt_public_key=(
                demo_profile.alert_provider_receipt_public_key if demo_profile is not None else ""
            ),
            alert_human_ack_public_key=(
                demo_profile.alert_human_ack_public_key if demo_profile is not None else ""
            ),
            alert_escalation_public_key=(
                demo_profile.alert_escalation_public_key if demo_profile is not None else ""
            ),
            canary_activation_path=(
                production_cfg.canary_activation_path if canary_runtime_binding else ""
            ),
            canary_operator_public_key=(
                production_cfg.canary_operator_public_key if canary_runtime_binding else ""
            ),
            canary_risk_public_key=(
                production_cfg.canary_risk_public_key if canary_runtime_binding else ""
            ),
            canary_check_verifier_public_key=(
                production_cfg.canary_check_verifier_public_key if canary_runtime_binding else ""
            ),
            canary_source_key_fingerprints=canary_runtime_binding.get(
                "source_key_fingerprints",
                {},
            ),
            canary_source_producer_inventory=canary_runtime_binding.get(
                "source_producer_inventory",
                {},
            ),
            canary_target_key_fingerprint=canary_runtime_binding.get(
                "target_key_fingerprint",
                "",
            ),
            canary_transition_sha256=canary_runtime_binding.get(
                "transition_sha256",
                "",
            ),
            canary_policy_sha256=canary_runtime_binding.get(
                "policy_sha256",
                "",
            ),
            canary_target_sha256=canary_runtime_binding.get(
                "target_sha256",
                "",
            ),
            account_lease=account_lease,
        )
        public_instruments = list(production_cfg.allowed_instruments)
        if not public_instruments and args.inst:
            public_instruments = [item.strip() for item in args.inst.split(",") if item.strip()]
        if public_instruments:
            production_runtime.register_public_market_data(
                public_instruments,
                args.bar,
            )
        journal.record_event(
            "production_config_loaded",
            payload={
                "config_hash": ProductionRuntime.config_hash(cfg),
                "environment": production_cfg.environment,
                "shadow_mode": production_cfg.shadow_mode,
            },
        )
        try:
            production_runtime.start()
        except Exception as exc:
            logger.critical("生产恢复门禁失败，拒绝启动策略: %s", exc)
            raise SystemExit(1) from exc
        atexit.register(production_runtime.stop)
        if production_cfg.environment == "production" and not launch_authorized:
            journal.record_event(
                "production_safety_only_started",
                severity="critical",
                payload={"error": launch_error},
            )
            journal.enqueue_outbox(
                "page.production_safety_only_started",
                {"error": launch_error},
            )
            print(
                "生产准入/receipt 无效：safety kernel 已以 HALTED 启动；"
                "不会创建策略 worker 或执行 BUY。"
            )
            try:
                while True:
                    time.sleep(60)
            except KeyboardInterrupt:
                production_runtime.stop()
                return
    executor_cfg = cfg.get("executor", {})
    signal_timeout_s = _resolve_signal_timeout(cfg, executor_cfg, args.strategy)
    state_store = StateStore(state_dir=executor_cfg.get("state_dir", "state"))

    # 优先检测已有持仓（无论选币结果如何，已有持仓必须纳入监控）
    existing_positions: list[str] = []
    try:
        discovered = discover_positions(
            exchange,
            exchange.quote_ccy,
            strict=True,
        )
    except RuntimeError as e:
        logger.error("实盘启动前账户检查失败: %s", e)
        print("错误: 无法确认账户现有持仓，已拒绝启动交易。请检查网络和 API 权限。")
        raise SystemExit(1) from e
    for inst_id, balance in discovered:
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
    requested_instruments = [s.strip() for s in args.inst.split(",")] if args.inst else []
    for pos_inst in existing_positions:
        if pos_inst not in requested_instruments:
            if production_cfg.environment == "production":
                print(
                    f"  已有仓位 {pos_inst} 仅由 safety kernel/交易所保护监控；"
                    "未在 launch manifest 中，不启动策略 worker"
                )
            else:
                print(f"  已有持仓 {pos_inst} 自动加入交易列表")
    instruments = _strategy_instruments(
        requested_instruments,
        existing_positions,
        production=production_cfg.environment == "production",
    )

    if not instruments:
        print("错误: 无交易对可监控")
        sys.exit(1)
    if production_cfg.allowed_instruments:
        unauthorized = sorted(set(instruments) - set(production_cfg.allowed_instruments))
        if unauthorized:
            raise SystemExit(
                "交易对不在 production.allowed_instruments: " + ", ".join(unauthorized)
            )

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

        def strategy_factory():
            return make_strategy(args.strategy, cfg=cfg)

        if not use_dashboard:
            mode = "【模拟盘】" if simulated else "【实盘】"
            print(f"\n启动 {mode} 多币种实盘交易")
            print(f"交易对: {', '.join(instruments)}  策略: {args.strategy}  K 线周期: {args.bar}")
            print(
                f"风控: 最大仓位={risk_config.max_position_pct * 100:.0f}%  止损={risk_config.stop_loss_pct * 100:.1f}%"
            )
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
            production_runtime=production_runtime,
            strategy_revision=strategy_revision,
        )
        supervisor.run()
        if production_runtime is not None:
            production_runtime.stop()
        return

    # 单币种 → 现有 LiveTrader 逻辑（向后兼容）
    strategy = make_strategy(args.strategy, cfg=cfg)

    if not use_dashboard:
        mode = "【模拟盘】" if simulated else "【实盘】"
        print(f"\n启动 {mode} 实盘交易")
        print(f"交易对: {args.inst}  策略: {args.strategy}  K 线周期: {args.bar}")
        print(
            f"风控: 最大仓位={risk_config.max_position_pct * 100:.0f}%  止损={risk_config.stop_loss_pct * 100:.1f}%"
        )
        print("按 Ctrl+C 停止\n")

    trader = LiveTrader(
        exchange=exchange,
        strategy=strategy,
        inst_id=instruments[0],
        risk_config=risk_config,
        dashboard=use_dashboard,
        simulated=simulated,
        signal_timeout_s=signal_timeout_s,
        state_store=state_store,
        production_runtime=production_runtime,
        strategy_revision=strategy_revision,
    )
    trader.run(bar=args.bar, lookback=100, interval_seconds=args.interval)
    if production_runtime is not None:
        production_runtime.stop()


# -------------------------------------------------------------------------
# 子命令：查看可用交易对
# -------------------------------------------------------------------------


def cmd_list_pairs(args, cfg):
    from tabulate import tabulate

    from okx_quant.data.market import MarketDataFetcher

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
    for key, (_cls, cn_name, desc) in STRATEGY_REGISTRY.items():
        tag = f" {yellow('[AI]')}" if is_llm_strategy(key) else ""
        print(f"  {bold(key):<20} {cn_name}{tag}")
        print(f"  {'':20} {dim(desc)}\n")


def _open_production_journal(cfg, *, read_only: bool = False):
    from okx_quant.config import ProductionSettings
    from okx_quant.infrastructure.db import SQLiteJournal

    settings = ProductionSettings.from_config(
        cfg,
        require_credentials=False,
        require_external_controls=False,
    )
    path = Path(settings.journal_path)
    if not path.is_file() or path.is_symlink():
        raise SystemExit(f"交易日志不存在或不是普通文件: {path}")
    journal = SQLiteJournal(
        path,
        must_exist=True,
        read_only=read_only,
    )
    if settings.environment == "production":
        if not settings.account_id:
            journal.close()
            raise SystemExit("生产运维命令必须加载 production.account_id")
        try:
            journal.assert_identity(settings.account_id)
        except Exception:
            journal.close()
            raise
    return settings, journal


def cmd_init_journal(args, cfg):
    from okx_quant.application.approval import production_config_hash
    from okx_quant.config import ProductionSettings
    from okx_quant.infrastructure.db import SQLiteJournal

    settings = ProductionSettings.from_config(
        cfg,
        require_credentials=False,
    )
    expected = f"INIT {settings.account_id or settings.environment}"
    provided = args.confirm
    if not provided and sys.stdin.isatty():
        provided = input(f"输入 '{expected}' 初始化全新交易日志: ").strip()
    if provided != expected:
        raise SystemExit(f"确认文本不匹配；必须是: {expected}")
    path = Path(settings.journal_path)
    if path.exists() or path.is_symlink():
        raise SystemExit(f"拒绝覆盖既有交易日志路径: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.parent.is_symlink() or not path.parent.is_dir():
        raise SystemExit("拒绝符号链接或非目录交易日志父路径")
    owner_uid = None
    owner_gid = None
    if settings.environment == "production":
        owner_user = getattr(args, "owner_user", "okxquant-trader")
        owner_group = getattr(args, "owner_group", "okxquant-data")
        owner_uid = pwd.getpwnam(owner_user).pw_uid
        owner_gid = grp.getgrnam(owner_group).gr_gid
        if os.geteuid() not in {0, owner_uid}:
            raise PermissionError("生产交易日志只能由 root 或目标 trader 身份初始化")
        os.chown(path.parent, owner_uid, owner_gid)
        path.parent.chmod(0o2750)
    with tempfile.NamedTemporaryFile(
        prefix=f".{path.name}.init-",
        suffix=".tmp",
        dir=path.parent,
        delete=False,
    ) as temporary_handle:
        temporary_path = Path(temporary_handle.name)
    try:
        journal = SQLiteJournal(temporary_path)
        try:
            journal.initialize_identity(
                account_id=settings.account_id or settings.environment,
                initial_config_hash=production_config_hash(settings, cfg),
                actor=args.actor,
            )
        finally:
            journal.close()
        if settings.environment == "production":
            if owner_uid is None or owner_gid is None:
                raise RuntimeError("生产交易日志 owner 解析状态非法")
            os.chown(temporary_path, owner_uid, owner_gid)
            temporary_path.chmod(0o640)
        else:
            temporary_path.chmod(0o600)
        with temporary_path.open("rb") as handle:
            os.fsync(handle.fileno())
        try:
            os.link(temporary_path, path)
        except FileExistsError as exc:
            raise SystemExit(f"拒绝覆盖并发创建的交易日志: {path}") from exc
        if settings.environment == "production":
            path.parent.chmod(0o2750)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        for suffix in ("", "-wal", "-shm"):
            Path(f"{temporary_path}{suffix}").unlink(missing_ok=True)
    print(f"交易日志已初始化并锁存 HALTED: {path}")


def cmd_resume_request(args, cfg):
    from okx_quant.application.approval import build_resume_request
    from okx_quant.config import ProductionSettings

    settings = ProductionSettings.from_config(
        cfg,
        require_credentials=False,
    )
    request = build_resume_request(
        settings,
        cfg,
        actor=args.actor,
        lifetime_s=args.expires_in,
    )
    output = Path(args.output)
    if output.exists() or output.is_symlink():
        raise SystemExit(f"拒绝覆盖既有恢复请求: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(request, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    output.chmod(0o600)
    print(f"恢复请求已生成（尚未批准）: {output}")


def cmd_flatten_request(args, cfg):
    from okx_quant.application.approval import build_control_request
    from okx_quant.config import ProductionSettings

    settings = ProductionSettings.from_config(
        cfg,
        require_credentials=False,
    )
    request = build_control_request(
        settings,
        cfg,
        action="flatten-and-cancel",
        actor=args.actor,
        instruments=args.inst or [],
        lifetime_s=args.expires_in,
    )
    output = Path(args.output)
    if output.exists() or output.is_symlink():
        raise SystemExit(f"拒绝覆盖既有 flatten 请求: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(request, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    output.chmod(0o600)
    print(f"flatten 请求已生成（尚未批准）: {output}")


def cmd_production_status(args, cfg):
    from okx_quant.cli.operations import render_json, status

    _, journal = _open_production_journal(cfg, read_only=True)
    try:
        print(render_json(status(journal)))
    finally:
        journal.close()


def cmd_audit_order(args, cfg):
    from okx_quant.cli.operations import render_json

    _, journal = _open_production_journal(cfg, read_only=True)
    try:
        print(render_json(journal.audit_order_chain(args.cl_ord_id)))
    finally:
        journal.close()


def cmd_halt_entries(args, cfg):
    from okx_quant.cli.operations import halt_entries, render_json

    _, journal = _open_production_journal(cfg)
    try:
        result = halt_entries(
            journal,
            actor=args.actor,
            timeout_s=args.wait,
        )
        print(render_json(result))
        if result["status"] != "completed":
            raise SystemExit(2)
    finally:
        journal.close()


def cmd_resume_entries(args, cfg):
    from okx_quant.application.approval import (
        ResumeApprovalVerifier,
        production_config_hash,
    )
    from okx_quant.cli.operations import enqueue_and_wait, render_json

    settings, journal = _open_production_journal(cfg)
    approval_path = Path(args.approval)
    if (
        not approval_path.is_file()
        or approval_path.is_symlink()
        or approval_path.stat().st_size <= 0
    ):
        journal.close()
        raise SystemExit("恢复批准必须是既有非空普通文件且不能是符号链接")
    try:
        artifact = json.loads(approval_path.read_text(encoding="utf-8"))
        claims = artifact["payload"]
        command_id = claims["command_id"]
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        journal.close()
        raise SystemExit("恢复批准文件不是合法 artifact") from exc
    expected = f"RESUME {settings.account_id or settings.environment}"
    provided = args.confirm
    if not provided and sys.stdin.isatty():
        print("此操作会在全部安全检查通过后重新允许新增 BUY。")
        provided = input(f"输入 '{expected}' 二次确认: ").strip()
    if provided != expected:
        journal.close()
        raise SystemExit(f"确认文本不匹配；必须是: {expected}")
    if not settings.resume_approval_public_key:
        journal.close()
        raise SystemExit("未配置独立风险审批公钥，禁止恢复交易")
    verifier = ResumeApprovalVerifier(settings.resume_approval_public_key)
    try:
        verifier.verify(
            artifact,
            command_id=command_id,
            expected_account_id=settings.account_id or settings.environment,
            expected_config_hash=production_config_hash(settings, cfg),
        )
    except ValueError as exc:
        journal.close()
        raise SystemExit(str(exc)) from exc
    try:
        result = enqueue_and_wait(
            journal,
            "resume-entries",
            {"approval": artifact},
            timeout_s=args.wait,
            command_id=command_id,
        )
        print(render_json(result))
        if result["status"] != "completed":
            raise SystemExit(2)
    finally:
        journal.close()


def cmd_flatten(args, cfg):
    from okx_quant.application.approval import (
        ResumeApprovalVerifier,
        production_config_hash,
    )
    from okx_quant.cli.operations import enqueue_and_wait, render_json

    settings, journal = _open_production_journal(cfg)
    if settings.environment == "production" and not settings.account_id:
        journal.close()
        raise SystemExit(
            "生产 flatten 必须加载包含 OKX_ACCOUNT_ID 的受控环境文件；"
            "请使用 --env-file /etc/okx-quant/production.env"
        )
    approval_path = Path(args.approval)
    if (
        not approval_path.is_file()
        or approval_path.is_symlink()
        or approval_path.stat().st_size <= 0
    ):
        journal.close()
        raise SystemExit("flatten 批准必须是既有非空普通文件且不能是符号链接")
    try:
        artifact = json.loads(approval_path.read_text(encoding="utf-8"))
        command_id = artifact["payload"]["command_id"]
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        journal.close()
        raise SystemExit("flatten 批准文件不是合法 artifact") from exc
    expected = f"FLATTEN {settings.account_id or settings.environment}"
    provided = args.confirm
    if not provided and sys.stdin.isatty():
        print("此操作会取消挂单并市价卖出真实/模拟账户仓位。")
        provided = input(f"输入 '{expected}' 二次确认: ").strip()
    if provided != expected:
        journal.close()
        raise SystemExit(f"确认文本不匹配；必须是: {expected}")
    if not settings.resume_approval_public_key:
        journal.close()
        raise SystemExit("未配置独立风险审批公钥，禁止 flatten")
    verifier = ResumeApprovalVerifier(settings.resume_approval_public_key)
    try:
        verifier.verify(
            artifact,
            command_id=command_id,
            expected_account_id=settings.account_id or settings.environment,
            expected_config_hash=production_config_hash(settings, cfg),
            expected_action="flatten-and-cancel",
            expected_instruments=args.inst or [],
        )
    except ValueError as exc:
        journal.close()
        raise SystemExit(str(exc)) from exc
    try:
        result = enqueue_and_wait(
            journal,
            "flatten-and-cancel",
            {"instruments": args.inst or [], "approval": artifact},
            timeout_s=args.wait,
            command_id=command_id,
        )
        print(render_json(result))
        if result["status"] != "completed":
            raise SystemExit(2)
    finally:
        journal.close()


def cmd_reconcile_now(args, cfg):
    from okx_quant.cli.operations import enqueue_and_wait, render_json

    _, journal = _open_production_journal(cfg)
    try:
        result = enqueue_and_wait(journal, "reconcile-now", {}, timeout_s=args.wait)
        print(render_json(result))
        if result["status"] != "completed":
            raise SystemExit(2)
    finally:
        journal.close()


def cmd_demo_probe(args, cfg):
    from okx_quant.cli.operations import enqueue_and_wait, render_json

    settings, journal = _open_production_journal(cfg)
    try:
        if settings.environment != "demo" or settings.shadow_mode:
            raise SystemExit("demo-probe 只允许 production.environment=demo 且 shadow_mode=false")
        if args.confirm != "I_UNDERSTAND_DEMO_PROBE":
            raise SystemExit("--confirm 必须精确等于 I_UNDERSTAND_DEMO_PROBE")
        payload = {"probe_id": args.probe_id}
        if not args.probe_id:
            if not args.inst:
                raise SystemExit("新 probe 必须提供 --inst")
            payload.update(
                {
                    "inst_id": args.inst,
                    "nominal_usdt": str(args.nominal_usdt),
                    "slot": args.slot,
                }
            )
        result = enqueue_and_wait(
            journal,
            "demo-probe",
            payload,
            timeout_s=args.wait,
        )
        print(render_json(result))
        if result["status"] != "completed":
            raise SystemExit(2)
    finally:
        journal.close()


def cmd_backup_now(args, cfg):
    from okx_quant.cli.operations import backup_now

    settings, journal = _open_production_journal(cfg)
    try:
        destination = backup_now(journal, args.destination or settings.backup_dir)
        print(destination)
    finally:
        journal.close()


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

    print(f"\n{'=' * 50}")
    print("  LLM 回测费用预估")
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
        est_cost = _estimate_cost(cheap_model, cheap_in, cheap_out) + _estimate_cost(
            deep_model, deep_in, deep_out
        )
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
        print(
            f"  预估 Token 上限: ~{est_input_tokens + est_output_tokens:,} ({est_input_tokens:,} in + {est_output_tokens:,} out)"
        )
        print(f"  预估费用上限: ~${est_cost:.4f} USD")

    if is_ensemble:
        print("  注: 集成策略仅在传统策略达成共识时调用 LLM，实际费用通常远低于预估")
    print(f"{'=' * 50}")

    confirm = input("\n  确认运行 LLM 回测? (y/N): ").strip().lower()
    if confirm != "y":
        print("已取消")
        sys.exit(0)


def _print_llm_usage(strategy):
    """回测结束后打印 LLM 用量统计"""
    from okx_quant.strategy.multi_agent_strategy import MultiAgentStrategy

    usage = strategy.get_usage_summary()
    model = strategy.llm_model

    print(f"\n{'=' * 50}")
    print("  LLM 用量统计")
    print(f"  模型: {model}")
    print(f"  总调用次数: {usage['total_calls']}")
    print(
        f"  总 Token: {usage['total_tokens']:,} ({usage['total_input_tokens']:,} in + {usage['total_output_tokens']:,} out)"
    )

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
        actual_cost = _estimate_cost(
            model, usage["total_input_tokens"], usage["total_output_tokens"]
        )
        print(f"  预估实际费用: ~${actual_cost:.4f} USD")

    print(f"{'=' * 50}")


# -------------------------------------------------------------------------
# 工具函数
# -------------------------------------------------------------------------


def _bar_to_minutes(bar: str) -> int:
    mapping = {
        "1m": 1,
        "3m": 3,
        "5m": 5,
        "15m": 15,
        "30m": 30,
        "1H": 60,
        "2H": 120,
        "4H": 240,
        "6H": 360,
        "12H": 720,
        "1D": 1440,
        "1W": 10080,
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
    parser.add_argument(
        "--env-file",
        default="",
        help="安全加载 systemd KEY=VALUE 环境文件（不执行 shell）",
    )
    parser.add_argument(
        "--log-level",
        default="",
        help="日志级别（默认读取 logging.level）",
    )
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
    p_live.add_argument(
        "--max-price", type=float, default=0, help="选币最大单价过滤 (USDT，0=不过滤)"
    )
    p_live.add_argument(
        "-y", "--yes", action="store_true", help="跳过交易对确认 prompt（自动化必用）"
    )
    p_live.add_argument(
        "--safety-only",
        action="store_true",
        help=argparse.SUPPRESS,
    )

    # screen
    p_screen = subparsers.add_parser("screen", help="因子选币器")
    p_screen.add_argument("--top", type=int, default=5, help="选出 top N 交易对")
    p_screen.add_argument("--bar", default="4H", help="K 线周期")
    p_screen.add_argument("--min-vol", type=float, default=None, help="最小 24H 成交额 (USDT)")
    p_screen.add_argument(
        "--max-price", type=float, default=0, help="最大单价过滤 (USDT，0=不过滤)"
    )

    # list-pairs
    subparsers.add_parser("list-pairs", help="查看可用交易对")

    # list-strategies
    subparsers.add_parser("list-strategies", help="查看可用策略")

    subparsers.add_parser("production-status", help="查看生产内核安全状态")

    p_init = subparsers.add_parser("init-journal", help="一次性初始化全新交易日志并锁存 HALTED")
    p_init.add_argument("--confirm", default="")
    p_init.add_argument("--actor", default=os.environ.get("USER", "unknown"))
    p_init.add_argument("--owner-user", default="okxquant-trader")
    p_init.add_argument("--owner-group", default="okxquant-data")

    p_audit = subparsers.add_parser("audit-order", help="查询 clOrdId 完整审计链")
    p_audit.add_argument("cl_ord_id")

    p_halt = subparsers.add_parser("halt-entries", help="停止所有新 BUY")
    p_halt.add_argument("--actor", default=os.environ.get("USER", "unknown"))
    p_halt.add_argument("--wait", type=float, default=30)

    p_resume_request = subparsers.add_parser(
        "resume-request", help="生成待独立风险审批人签名的短效恢复请求"
    )
    p_resume_request.add_argument("--actor", default=os.environ.get("USER", "unknown"))
    p_resume_request.add_argument("--expires-in", type=int, default=300)
    p_resume_request.add_argument("--output", required=True)

    p_resume = subparsers.add_parser(
        "resume-entries",
        help="提交独立签名批准并通过完整安全检查后恢复 BUY",
    )
    p_resume.add_argument("--confirm", default="")
    p_resume.add_argument("--approval", required=True)
    p_resume.add_argument("--wait", type=float, default=60)

    p_flatten_request = subparsers.add_parser(
        "flatten-request", help="生成待独立风险审批人签名的短效 flatten 请求"
    )
    p_flatten_request.add_argument("--inst", action="append", default=[])
    p_flatten_request.add_argument("--actor", default=os.environ.get("USER", "unknown"))
    p_flatten_request.add_argument("--expires-in", type=int, default=300)
    p_flatten_request.add_argument("--output", required=True)

    p_flatten = subparsers.add_parser(
        "flatten-and-cancel", help="取消挂单并退出仓位（需要二次确认）"
    )
    p_flatten.add_argument("--inst", action="append", default=[])
    p_flatten.add_argument("--confirm", default="")
    p_flatten.add_argument("--approval", required=True)
    p_flatten.add_argument("--wait", type=float, default=60)

    p_reconcile = subparsers.add_parser("reconcile-now", help="请求立即对账")
    p_reconcile.add_argument("--wait", type=float, default=60)

    p_probe = subparsers.add_parser(
        "demo-probe",
        help="通过长期运行的 production path 执行或恢复受限 Demo probe",
    )
    p_probe.add_argument("--probe-id", default="")
    p_probe.add_argument("--inst", default="")
    p_probe.add_argument("--nominal-usdt", type=Decimal, default=Decimal("5"))
    p_probe.add_argument("--slot", type=int, choices=(1, 2), default=1)
    p_probe.add_argument("--confirm", required=True)
    p_probe.add_argument("--wait", type=float, default=60)

    p_backup = subparsers.add_parser("backup-now", help="创建并校验 SQLite 在线备份")
    p_backup.add_argument("--destination", default="")

    args = parser.parse_args()

    # 无子命令时进入交互向导
    if args.command is None:
        from okx_quant.cli.wizard import run_wizard

        command, params = run_wizard()
        args.command = command
        for k, v in params.items():
            setattr(args, k, v)

    load_env_file(args.env_file)
    cfg = load_config(args.config)
    log_cfg = cfg.get("logging", {})
    production_logging = bool(cfg.get("production", {}).get("enabled", False))
    effective_log_level = args.log_level or log_cfg.get("level", "INFO")
    if (
        cfg.get("production", {}).get("environment") == "production"
        and str(effective_log_level).upper() == "DEBUG"
    ):
        parser.error("生产环境禁止 DEBUG 日志")
    okx_secrets = cfg.get("okx", {})
    setup_logging(
        effective_log_level,
        log_cfg.get("file", ""),
        structured=production_logging,
        secrets=[
            okx_secrets.get("api_key", ""),
            okx_secrets.get("secret_key", ""),
            okx_secrets.get("passphrase", ""),
            cfg.get("llm", {}).get("api_key", ""),
            cfg.get("llm_deep", {}).get("api_key", ""),
        ],
    )

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
    elif args.command == "production-status":
        cmd_production_status(args, cfg)
    elif args.command == "init-journal":
        cmd_init_journal(args, cfg)
    elif args.command == "audit-order":
        cmd_audit_order(args, cfg)
    elif args.command == "halt-entries":
        cmd_halt_entries(args, cfg)
    elif args.command == "resume-request":
        cmd_resume_request(args, cfg)
    elif args.command == "resume-entries":
        cmd_resume_entries(args, cfg)
    elif args.command == "flatten-request":
        cmd_flatten_request(args, cfg)
    elif args.command == "flatten-and-cancel":
        cmd_flatten(args, cfg)
    elif args.command == "reconcile-now":
        cmd_reconcile_now(args, cfg)
    elif args.command == "demo-probe":
        cmd_demo_probe(args, cfg)
    elif args.command == "backup-now":
        cmd_backup_now(args, cfg)


if __name__ == "__main__":
    main()
