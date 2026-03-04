# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

OKX quantitative cryptocurrency trading system (Chinese-language UI). Supports strategy backtesting, live/simulated trading with a terminal dashboard, and LLM-powered AI strategies. Spot-only, long-only, USDT-quoted pairs.

## Commands

```bash
# Install dependencies
uv sync

# Run (interactive wizard)
uv run python main.py

# Backtest
uv run python main.py backtest --inst DOGE-USDT --strategy bollinger --bar 4H --days 30

# Live trading (with terminal dashboard)
uv run python main.py live --inst DOGE-USDT --strategy bollinger --bar 4H --interval 10

# Live trading (log mode)
uv run python main.py live --inst DOGE-USDT --strategy bollinger --bar 4H --no-dashboard

# View ticker / list pairs / list strategies
uv run python main.py ticker --inst BTC-USDT
uv run python main.py list-pairs
uv run python main.py list-strategies
```

Python 3.12, managed with `uv`. No test suite exists yet.

## Architecture

### Entry Point & Config

`main.py` — CLI with argparse subcommands (`ticker`, `backtest`, `live`, `list-pairs`, `list-strategies`). Falls back to interactive wizard (`okx_quant/cli/wizard.py`) when no subcommand given. Loads `config.yaml` (copy from `config.yaml.example`).

### Core Package: `okx_quant/`

**`client/`** — OKX V5 REST API client (`rest.py`) with HMAC-SHA256 auth. Public endpoints need no API key; private endpoints (account/trade) require key+secret+passphrase. `simulated=True` sends `x-simulated-trading: 1` header. WebSocket client stub in `websocket.py`.

**`data/`** — `market.py`: `MarketDataFetcher` wraps REST client, returns pandas DataFrames. Auto-paginates history candles (OKX max 300/request). K-line DataFrame columns: `ts, open, high, low, close, vol, vol_ccy`. `news.py`: `CryptoNewsFetcher` pulls from CryptoPanic API with 5-min memory cache.

**`indicators/`** — Pure pandas functions: `trend.py` (sma, ema, macd, bollinger_bands, atr), `momentum.py` (rsi, stochastic, cci). Imported via `okx_quant.indicators`.

**`strategy/`** — Strategy pattern via `BaseStrategy` abstract class. Subclasses implement `generate_signal(df, inst_id) -> Signal`. Strategies are stateless (no position tracking). Registered in `STRATEGY_REGISTRY` dict in `__init__.py`.

Available strategies:
- `ma_cross` — EMA 9/21 crossover with ATR-based SL/TP
- `rsi_mean` — RSI overbought/oversold mean reversion
- `bollinger` — Bollinger Band breakout with RSI filter
- `llm` — LLM analyzes technicals + news, returns JSON decision. Requires `set_llm_client()` injection. Safety: confidence < 0.6 or API failure falls back to HOLD.
- `ensemble` — Traditional strategies vote (consensus >= 2/3), then LLM confirms. Only calls LLM when consensus exists (saves API costs).

**`backtest/`** — `BacktestEngine` iterates K-lines, calls strategy per bar, simulates fills with fee+slippage. Spot-only, one position at a time. SL/TP checked intra-bar. `BacktestReport` prints metrics (Sharpe, max drawdown, win rate, profit factor).

**`trading/`** — `LiveTrader` in `executor.py`: poll-based live trading loop. Fetches candles → strategy signal → risk check → market order via REST. Supports terminal dashboard mode.

**`risk/`** — `RiskManager`: pre-trade checks (max position %, min order size, position count limit), SL/TP calculation, max drawdown halt. `RiskConfig` dataclass for parameters.

**`llm/`** — `LLMClient` supports OpenAI/DeepSeek (chat/completions) and Claude (Messages API). Provider auto-detected from config. `LLMConfig.from_dict()` for config loading.

**`cli/`** — `dashboard.py`: ANSI terminal dashboard with box-drawing, CJK-aware width calculations. `colors.py`: ANSI color helpers. `wizard.py`: interactive menu.

### Adding a New Strategy

1. Create `okx_quant/strategy/my_strategy.py` with a class extending `BaseStrategy`
2. Implement `generate_signal(df, inst_id) -> Signal`
3. Register in `okx_quant/strategy/__init__.py` `STRATEGY_REGISTRY` dict
4. If LLM-based, add class to `_LLM_STRATEGY_CLASSES` tuple and implement `set_llm_client()`/`set_news_fetcher()` dependency injection

### Key Conventions

- All user-facing text is in Chinese
- K-line DataFrames always sorted ascending by `ts`
- Signal dataclass: `signal` (BUY/SELL/HOLD), `inst_id`, `price`, `size_pct`, `stop_loss`, `take_profit`, `reason`
- OKX API responses checked for `code != "0"` and raised as `RuntimeError`
- `config.yaml` contains secrets (API keys) — never commit it; `config.yaml.example` is the template
