#!/usr/bin/env python3
"""Generate a balanced, preregistered formal Demo probe schedule."""

from __future__ import annotations

import argparse
import json
import secrets
import uuid
from datetime import UTC, date, datetime, time, timedelta
from pathlib import Path

from okx_quant.application.demo_probe import (
    FORMAL_PROBE_DAYS,
    FORMAL_SPREAD_BUCKETS,
    FORMAL_VOLATILITY_BUCKETS,
    validate_formal_probe_schedule,
)


def _day(value: str) -> date:
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("start-day 必须为 YYYY-MM-DD") from exc


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--start-day", required=True, type=_day)
    parser.add_argument("--days", type=int, default=FORMAL_PROBE_DAYS)
    parser.add_argument("--inst", action="append", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.days != FORMAL_PROBE_DAYS:
        raise ValueError("formal schedule 必须精确为 30 日")
    instruments = sorted(set(args.inst))
    if (
        not instruments
        or len(instruments) != len(args.inst)
        or any(not item.endswith("-USDT") for item in instruments)
    ):
        raise ValueError("--inst 必须是唯一的 *-USDT 交易对")
    if args.output.exists() or args.output.is_symlink():
        raise RuntimeError("拒绝覆盖 probe schedule")
    created = datetime.now(UTC)
    if datetime.combine(args.start_day, time.min, tzinfo=UTC) <= created:
        raise ValueError("start-day 必须晚于 schedule 创建日")
    random = secrets.SystemRandom()
    slots = []
    # 30 days cannot divide evenly across 16 joint cells. Start with two
    # observations per cell, then remove exactly two cells while preserving
    # every marginal: distinct UTC bins, spread buckets and volatility
    # buckets. The resulting 4×2×2 cell counts are all one or two.
    joint_cells = [
        (time_bin, spread, volatility)
        for _cycle in range(2)
        for time_bin in range(4)
        for spread in FORMAL_SPREAD_BUCKETS
        for volatility in FORMAL_VOLATILITY_BUCKETS
    ]
    removed_time_bins = random.sample(range(4), 2)
    removed_spreads = list(FORMAL_SPREAD_BUCKETS)
    removed_volatilities = list(FORMAL_VOLATILITY_BUCKETS)
    random.shuffle(removed_spreads)
    random.shuffle(removed_volatilities)
    for cell in zip(
        removed_time_bins,
        removed_spreads,
        removed_volatilities,
        strict=True,
    ):
        joint_cells.remove(cell)
    random.shuffle(joint_cells)
    offset = random.randrange(len(instruments))
    for index in range(args.days):
        day = args.start_day + timedelta(days=index)
        time_bin, spread, volatility = joint_cells[index]
        # The four-hour observation window must remain inside the same UTC
        # day. The final 18:00-24:00 bin therefore starts at 18:00 or 19:00.
        hour = time_bin * 6 + random.randrange(
            0,
            2 if time_bin == 3 else 6,
        )
        minute = random.randrange(0, 60)
        started = datetime.combine(
            day,
            time(hour=hour, minute=minute),
            tzinfo=UTC,
        )
        slots.append({
            "day": day.isoformat(),
            "slot": 1,
            "inst_id": instruments[(index + offset) % len(instruments)],
            "direction": "buy_then_exit",
            "window_start": started.isoformat(),
            "window_end": (started + timedelta(hours=4)).isoformat(),
            "spread_min_bps": spread[0],
            "spread_max_bps": spread[1],
            "volatility_min_bps": volatility[0],
            "volatility_max_bps": volatility[1],
        })
    schedule = validate_formal_probe_schedule({
        "version": 2,
        "action": "precommit-demo-probe-schedule",
        "schedule_id": f"formal-{uuid.uuid4().hex}",
        "created_at": created.isoformat(),
        "slots": slots,
    })
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(schedule, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    args.output.chmod(0o600)
    print(args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
