# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

OKX quantitative cryptocurrency trading system (Chinese-language UI). Supports strategy backtesting, live/simulated trading with a terminal dashboard, factor-based coin screening, and LLM-powered AI strategies (single-LLM and multi-agent). Spot-only, long-only, USDT-quoted pairs.

Python 3.12, managed with `uv`.

## Commands

```bash
uv sync                                    # install deps

# Run interactive wizard (no subcommand)
uv run python main.py

# Backtest / live / screen / info
uv run python main.py backtest --inst DOGE-USDT --strategy bollinger --bar 4H --days 30
uv run python main.py live --inst DOGE-USDT,BTC-USDT --strategy ma_cross --bar 15m --interval 10
uv run python main.py live --inst DOGE-USDT --strategy bollinger --bar 4H --no-dashboard   # log mode
uv run python main.py live --strategy ma_cross --screen 5 --bar 1H    # auto-pick 5 pairs via screener
uv run python main.py screen --top 5 --bar 4H
uv run python main.py ticker --inst BTC-USDT
uv run python main.py list-pairs
uv run python main.py list-strategies
```

CLI subcommands live in `main.py` (`cmd_*` functions): `ticker`, `backtest`, `live`, `screen`, `list-pairs`, `list-strategies`. Global flags: `--config` (default `config.yaml`), `--log-level`.

### Tests

A `pytest` suite exists under `tests/` (configured in `pyproject.toml`, markers `unit` / `integration`).

```bash
uv run pytest                              # all tests
uv run pytest -m unit                      # fast, no network
uv run pytest tests/test_backtest_engine.py -k name   # single test
```

Tests use `tests/conftest.py` (`synthetic_ohlcv` fixture) and `okx_quant/exchange/fake.py` (`FakeExchange`) — no live API calls.

### Quant research scripts (`scripts/`)

```bash
uv run python scripts/backtest_grid.py            # grid backtest: N strategies × M coins × K bars (parquet cache, --resume, --dry-run)
uv run python scripts/backtest_report.py          # rank grid results by raw Sharpe
uv run python scripts/backtest_analyze_alpha.py   # HODL-adjusted analysis, rank by alpha_sharpe
uv run python scripts/param_sweep.py --from-grid  # parameter sensitivity (real edge vs overfit)
uv run python scripts/test_api.py                 # OKX API connectivity/trade-capability diagnostic
```

## Configuration

`config.yaml` (copy from `config.yaml.example`) holds secrets and is gitignored. `okx_quant/config.py` `load_yaml()` expands `${VAR}` and `${VAR:-default}` env-var references inside the YAML — production injects secrets via env (`OKX_API_KEY`, `OKX_SECRET_KEY`, `OKX_PASSPHRASE`, `LLM_API_KEY`) rather than literals. Key sections: `okx` (creds + `simulated`), `llm` / `llm_deep` (cheap vs strong model for multi-agent), `risk`, `multi_agent`, `screener`. Live real-trading (`simulated: false`) requires typing `I UNDERSTAND`, or env `OKX_LIVE_CONFIRMED=1` for unattended systemd runs.

Production deployment (systemd on a DigitalOcean droplet, `verify_deploy.sh` / `summary.sh` ops helpers) is documented in `README.md` — consult it before touching deploy.

## Architecture

`okx_quant/` package layers, roughly bottom-up:

**`client/`** — Raw OKX V5 REST client (`rest.py`, HMAC-SHA256 auth; `simulated=True` sends `x-simulated-trading: 1`). WebSocket stub in `websocket.py`. Low-level; most trading code goes through the `exchange/` layer instead.

**`exchange/`** — Exchange-neutral abstraction (`base.py` `Exchange` Protocol + dataclasses `BalanceSnapshot`, `Holding`, `Ticker`, `Candle`, `OrderResult`). `okx.py` `OKXExchange` adapts `OKXRestClient` + `MarketDataFetcher`; `fake.py` `FakeExchange` is the in-memory test double. **Trading code depends on `Exchange`, not `client/rest.py` directly** (`LiveTrader` wraps a bare client in `OKXExchange` for back-compat).

**`data/`** — `market.py` `MarketDataFetcher` (REST → pandas DataFrames; auto-paginates history candles, OKX max 300/req; columns `ts, open, high, low, close, vol, vol_ccy`, always ascending by `ts`). `news.py` `CryptoNewsFetcher` (CryptoPanic, 5-min cache). `screener.py` `Screener` — 3-layer coin selection: hard filters (volume/age/price/stablecoin exclusion) → factor scoring (ADX, ATR%, volume ratio, ROC, Bollinger bandwidth) → correlation de-dup (skip pairs with corr ≥ 0.85).

**`indicators/`** — Pure pandas: `trend.py` (sma, ema, macd, bollinger_bands, atr, adx), `momentum.py` (rsi, stochastic, cci). `cache.py` provides `cached_*` wrappers + `populate_cache()`/`slice_cache()`: the backtest pre-computes indicators once on the full frame and serves cached slices (avoids O(n²) recompute). Live ticks miss the cache and fall through to direct computation.

**`strategy/`** — `BaseStrategy` abstract class; subclasses implement `generate_signal(df, inst_id) -> Signal`. Stateless (no position tracking). Registered in `STRATEGY_REGISTRY` (`__init__.py`):
- `ma_cross` — EMA 9/21 crossover, ATR SL/TP
- `rsi_mean` — RSI mean reversion
- `bollinger` — Bollinger breakout + RSI filter
- `adaptive` — detects regime (ADX + Bollinger bandwidth), switches between MACross/Bollinger/RSIMean sub-strategies; cooldown anti-flip-flop
- `trend_momentum` — multi-indicator trend confirmation, trailing stop (TP left to executor)
- `llm` — single LLM analyzes technicals + news → JSON decision; confidence < 0.6 or API failure → HOLD
- `ensemble` — traditional strategies vote (consensus ≥ 2/3) then LLM confirms (only calls LLM on consensus)
- `multi_agent` — thin wrapper over `agentic/` pipeline

**`agentic/`** — Multi-agent LLM pipeline (TradingAgents-inspired). `pipeline.py` `AgenticPipeline` orchestrates 8 agents (`agents.py`): 4 analysts in parallel (cheap model) → bull/bear debate → trader decision → risk-manager veto (strong model). `config.py`, `prompts.py`, `token_tracker.py` (thread-safe budget cap → abort to HOLD). **Full design doc: `Agent.md`.** Cheap vs strong model split via `llm` / `llm_deep` config.

**`backtest/`** — `BacktestEngine` iterates K-lines, calls strategy per bar, simulates fills with fee + slippage; spot-only, one position at a time, intra-bar SL/TP. `BacktestReport` prints Sharpe, max drawdown, win rate, profit factor.

**`trading/`** — Live execution. `executor.py` `LiveTrader` is the per-instrument poll loop: fetch candles → update equity → `PositionMonitor` SL/TP check → strategy signal → `OrderExecutor` → persist state. Supporting modules:
- `supervisor.py` `Supervisor` — multi-instrument coordinator: one `LiveTrader` per pair as worker threads sharing one `RiskManager` + `Exchange`; main thread renders dashboard. Single pair uses `LiveTrader` directly; comma-separated/`--screen` switches to `Supervisor`.
- `orders.py` `OrderExecutor` — lot-size rounding, market orders, buy/sell cooldown, phantom-position cleanup (OKX error 51008)
- `position_monitor.py` `PositionMonitor` — SL/TP + trailing stop (highest − N×ATR)
- `account.py` `AccountSnapshot` — TTL-cached balance, invalidated after trades
- `state.py` `StateStore` / `TraderState` — atomic JSON persistence (highest_since_entry, cooldown timers, last signal, tick count); validates `inst_id` against whitelist + path-escape guard
- `position_restore.py` — on startup, discovers existing account holdings and syncs them into `RiskManager`; filters dust (< $1 USDT) so leftover OKX balances don't pollute monitoring
- `decision_log.py` `DecisionLogger` — per-inst/per-day CSV with LRU dedup

**`risk/`** — `RiskManager`: pre-trade checks (max position %, min order size, max open positions), SL/TP calc, max-drawdown halt. `RiskConfig` dataclass.

**`llm/`** — `LLMClient` for OpenAI/DeepSeek (chat/completions) and Claude (Messages API); provider auto-detected. `LLMConfig.from_dict()`. Note: Claude path needs an API key, not OAuth.

**`cli/`** — `dashboard.py` (ANSI box-drawing dashboard, CJK-aware width), `colors.py`, `wizard.py` (interactive menu).

**`utils/`** — `timeout.py` (wraps strategy calls so a slow LLM can't block the loop).

## Adding a New Strategy

1. Create `okx_quant/strategy/my_strategy.py` extending `BaseStrategy`, implement `generate_signal(df, inst_id) -> Signal`. Use `cached_*` from `indicators/cache.py` for indicators (free backtest speedup).
2. Register in `STRATEGY_REGISTRY` (`okx_quant/strategy/__init__.py`) as `key: (Class, 中文名, 描述)`.
3. If LLM-based, add the class to `_LLM_STRATEGY_CLASSES` and implement `set_llm_client()` / `set_news_fetcher()` injection.

## Key Conventions

- All user-facing text is in Chinese (commit messages too, mixed zh/en, conventional-commits style).
- K-line DataFrames always sorted ascending by `ts`.
- `Signal` dataclass: `signal` (BUY/SELL/HOLD), `inst_id`, `price`, `size_pct`, `stop_loss`, `take_profit`, `reason`.
- OKX API responses: check `code != "0"` and raise `RuntimeError`.
- New trading/data code should target the `Exchange` protocol, not `client/rest.py`.
- `config.yaml` holds secrets — never commit it; `config.yaml.example` is the template.
