"""交互式向导 — 无参数运行时引导用户选择操作"""

import sys

from okx_quant.cli.colors import bold, cyan, dim, yellow
from okx_quant.strategy import STRATEGY_REGISTRY, is_llm_strategy

VALID_BARS = ["1m", "3m", "5m", "15m", "30m", "1H", "2H", "4H", "6H", "12H", "1D", "1W"]


def prompt(label: str, default: str = "", choices: list[str] | None = None) -> str:
    """通用输入提示，支持默认值和合法值校验"""
    hint = f" [{default}]" if default else ""
    if choices:
        hint += f" ({'/'.join(choices)})"
    while True:
        value = input(f"  {label}{hint}: ").strip()
        if not value:
            if default:
                return default
            print(yellow("    请输入值"))
            continue
        if choices and value not in choices:
            print(yellow(f"    无效选项，可选: {', '.join(choices)}"))
            continue
        return value


def prompt_inst(default: str = "BTC-USDT", allow_multi: bool = False) -> str:
    """交易对输入，allow_multi=True 时支持逗号分隔多个交易对"""
    hint = "（多个用逗号分隔）" if allow_multi else ""
    value = prompt(f"交易对{hint}", default)
    parts = [p.strip().upper() for p in value.split(",")]
    for p in parts:
        if "-" not in p:
            print(yellow(f"    格式应为 XXX-USDT，如 BTC-USDT（输入的 {p} 无效）"))
            return prompt_inst(default, allow_multi)
    return ",".join(parts)


def prompt_bar(default: str = "4H") -> str:
    """K 线周期选择"""
    return prompt("K 线周期", default, VALID_BARS)


def prompt_strategy() -> str:
    """带编号的策略选择菜单"""
    keys = list(STRATEGY_REGISTRY.keys())
    print()
    for i, key in enumerate(keys, 1):
        _, cn_name, desc = STRATEGY_REGISTRY[key]
        tag = f" {yellow('[AI]')}" if is_llm_strategy(key) else ""
        print(f"    [{i}] {key:<12} {cn_name}{tag}  {dim(desc)}")
    print()
    while True:
        value = input(f"  选择策略 [1-{len(keys)}，默认 1]: ").strip()
        if not value:
            return keys[0]
        if value.isdigit():
            idx = int(value) - 1
            if 0 <= idx < len(keys):
                return keys[idx]
        if value in keys:
            return value
        print(yellow(f"    无效选择"))


def _wizard_ticker() -> tuple[str, dict]:
    print(cyan("\n  — 查看行情 —\n"))
    inst = prompt_inst()
    return "ticker", {"inst": inst}


def _wizard_backtest() -> tuple[str, dict]:
    print(cyan("\n  — 策略回测 —\n"))
    inst = prompt_inst("DOGE-USDT")
    strategy = prompt_strategy()
    bar = prompt_bar("4H")
    days = prompt("回测天数", "180")
    return "backtest", {
        "inst": inst,
        "strategy": strategy,
        "bar": bar,
        "days": int(days),
        "export_csv": "",
    }


def prompt_max_price() -> float:
    """询问单价过滤，返回最大单价（0 = 不过滤）"""
    value = prompt("最大单价过滤（USDT，0=不过滤）", "0")
    try:
        v = float(value)
        return max(v, 0)
    except ValueError:
        print(yellow("    请输入数字"))
        return prompt_max_price()


def _wizard_screen() -> tuple[str, dict]:
    print(cyan("\n  — 因子选币 —\n"))
    top_n = int(prompt("选出 top N 交易对", "5"))
    bar = prompt_bar("4H")
    max_price = prompt_max_price()
    return "screen", {
        "top": top_n,
        "bar": bar,
        "min_vol": None,
        "max_price": max_price,
    }


def _wizard_live() -> tuple[str, dict]:
    print(cyan("\n  — 实盘交易 —\n"))

    # 自动选币
    auto_screen = prompt("是否自动选币？", "n", ["y", "n"])
    screen_n = 0
    max_price = 0.0
    inst = ""
    if auto_screen == "y":
        screen_n = int(prompt("选出 top N 交易对", "5"))
        max_price = prompt_max_price()
    else:
        inst = prompt_inst("DOGE-USDT", allow_multi=True)

    strategy = prompt_strategy()
    bar = prompt_bar("1H")
    interval = prompt("轮询间隔（秒）", "60")
    return "live", {
        "inst": inst,
        "strategy": strategy,
        "bar": bar,
        "interval": int(interval),
        "no_dashboard": False,
        "screen": screen_n,
        "max_price": max_price,
    }


def run_wizard() -> tuple[str, dict]:
    """主入口 — 显示菜单，返回 (command, params_dict)"""
    print(bold(cyan("\n  OKX 量化交易系统 v1.0.0\n")))
    print("  [1] 查看行情")
    print("  [2] 策略回测")
    print("  [3] 实盘交易")
    print("  [4] 因子选币")
    print("  [5] 查看可用交易对")
    print("  [6] 查看可用策略")
    print(f"  [q] 退出\n")

    choice = input("  请选择 [1-6/q]: ").strip().lower()

    if choice == "1":
        return _wizard_ticker()
    elif choice == "2":
        return _wizard_backtest()
    elif choice == "3":
        return _wizard_live()
    elif choice == "4":
        return _wizard_screen()
    elif choice == "5":
        return "list-pairs", {}
    elif choice == "6":
        return "list-strategies", {}
    elif choice in ("q", "quit", "exit"):
        print("\n  再见！\n")
        sys.exit(0)
    else:
        print(yellow("\n  无效选择，请重试\n"))
        return run_wizard()
