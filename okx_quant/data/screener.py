"""因子选币器 — 三层漏斗筛选最优交易对

Layer 1: 硬过滤（流动性/上线时间/排除稳定币）
Layer 2: 因子打分（ADX/ATR%/量变比/ROC/带宽百分位）
Layer 3: 相关性去重（贪心去掉高度相关的币种）
"""

import logging
import time
from dataclasses import dataclass, field

import pandas as pd

from okx_quant.client.rest import OKXRestClient
from okx_quant.data.market import MarketDataFetcher
from okx_quant.indicators.trend import adx, atr, bollinger_bands

logger = logging.getLogger(__name__)

# 主流稳定币，筛选时排除
# 非 USD 前缀的稳定币/锚定资产（USD* 开头的自动排除，无需列出）
_DEFAULT_STABLECOINS = [
    "TUSD", "BUSD", "DAI", "FDUSD", "GUSD", "PYUSD",
    "EURT", "EUROC", "XAUT", "PAXG",
]


@dataclass
class ScreenerConfig:
    """选币器可调参数"""

    # --- Layer 1: 硬过滤 ---
    min_vol_24h_usdt: float = 500_000
    min_listing_days: int = 90
    exclude_stablecoins: list[str] = field(default_factory=lambda: list(_DEFAULT_STABLECOINS))
    pre_filter_top_n: int = 30
    max_price: float = 0           # 最大单价（0 = 不过滤）
    min_order_usdt: float = 0       # 最小下单金额（0 = 不过滤）
    available_usdt: float = 0       # 可用资金（0 = 不过滤）

    # --- Layer 2: 因子 ---
    bar: str = "4H"
    lookback: int = 100
    weight_adx: float = 0.30
    weight_atr_pct: float = 0.20
    weight_vol_ratio: float = 0.15
    weight_roc: float = 0.15
    weight_bandwidth_pctile: float = 0.20

    # --- Layer 3: 相关性 ---
    corr_threshold: float = 0.85

    @classmethod
    def from_dict(cls, d: dict) -> "ScreenerConfig":
        """从配置字典构建，忽略未知 key"""
        valid_keys = {f.name for f in cls.__dataclass_fields__.values()}
        return cls(**{k: v for k, v in d.items() if k in valid_keys})


class Screener:
    """因子选币器 — 三层漏斗"""

    def __init__(self, client: OKXRestClient, config: ScreenerConfig | None = None):
        self.client = client
        self.fetcher = MarketDataFetcher(client)
        self.cfg = config or ScreenerConfig()
        self._candle_cache: dict[str, pd.DataFrame] = {}

    # ------------------------------------------------------------------
    # 公共入口
    # ------------------------------------------------------------------

    def run(self, top_n: int = 5) -> tuple[list[str], pd.DataFrame]:
        """完整三层漏斗管线

        Returns:
            (选中的交易对列表, 含所有评分的 DataFrame)
        """
        print(f"\n{'='*55}")
        print(f"  因子选币器 — 三层漏斗筛选")
        print(f"  K 线周期: {self.cfg.bar}  回看: {self.cfg.lookback} 根")
        print(f"{'='*55}")

        # Layer 1
        candidates = self._hard_filter()
        if not candidates:
            print("\n  Layer 1 硬过滤后无候选交易对")
            return [], pd.DataFrame()

        # Layer 2
        scored_df = self._compute_factors(candidates)
        if scored_df.empty:
            print("\n  Layer 2 因子计算后无有效交易对")
            return [], pd.DataFrame()

        # Layer 3
        selected = self._correlation_filter(scored_df, top_n)

        return selected, scored_df

    # ------------------------------------------------------------------
    # Layer 1: 硬过滤
    # ------------------------------------------------------------------

    def _hard_filter(self) -> list[str]:
        """流动性 + 上线时间 + 排除稳定币 → 按成交额排序取 top N"""
        print(f"\n  [Layer 1] 硬过滤...")

        # 拉取全量 ticker
        tickers = self.fetcher.get_all_tickers()
        if tickers.empty:
            logger.error("无法获取 ticker 数据")
            return []

        # 仅保留 USDT 对
        usdt = tickers[tickers["inst_id"].str.endswith("-USDT")].copy()
        total_usdt = len(usdt)

        # 排除稳定币：USD* 前缀自动排除 + 显式列表
        stable_set = {f"{s}-USDT" for s in self.cfg.exclude_stablecoins}
        base_ccy = usdt["inst_id"].str.split("-").str[0]
        usdt = usdt[~base_ccy.str.startswith("USD") & ~usdt["inst_id"].isin(stable_set)]

        # 24H 成交额（vol_24h 是币本位，需 * last 转 USDT）
        usdt["vol_usdt"] = usdt["vol_24h"] * usdt["last"]
        usdt = usdt[usdt["vol_usdt"] >= self.cfg.min_vol_24h_usdt]

        # 单价过滤
        if self.cfg.max_price > 0:
            before = len(usdt)
            usdt = usdt[usdt["last"] <= self.cfg.max_price]
            filtered = before - len(usdt)
            if filtered > 0:
                print(f"    单价过滤: ≤ {self.cfg.max_price} USDT，排除 {filtered} 个")

        # 上线时间过滤：拉取 instrument 列表
        instruments = self.client.get_instruments("SPOT")
        if self.cfg.min_listing_days > 0:
            now_ms = time.time() * 1000
            min_list_ms = self.cfg.min_listing_days * 86400 * 1000
            valid_insts = set()
            for inst in instruments:
                list_time = int(inst.get("listTime", "0") or "0")
                if list_time > 0 and (now_ms - list_time) >= min_list_ms:
                    valid_insts.add(inst["instId"])
            usdt = usdt[usdt["inst_id"].isin(valid_insts)]

        # 资金量过滤：排除买不起的币种
        # 条件：max(minSz * price, last_price) > available_usdt
        # 即：最小下单金额或单价超过可用资金时排除
        if self.cfg.available_usdt > 0:
            min_sz_map = {}
            for inst in instruments:
                inst_id = inst["instId"]
                min_sz = float(inst.get("minSz", "0") or "0")
                if min_sz > 0:
                    min_sz_map[inst_id] = min_sz

            excluded_afford = []
            affordable_mask = []
            for _, row in usdt.iterrows():
                inst_id = row["inst_id"]
                price = row["last"]
                min_sz = min_sz_map.get(inst_id, 0)
                min_cost = max(min_sz * price, price)  # 至少买 1 个或 minSz 个
                if min_cost > self.cfg.available_usdt:
                    affordable_mask.append(False)
                    excluded_afford.append(f"{inst_id}(${price:.2f}/个,最小{min_cost:.1f}U)")
                else:
                    affordable_mask.append(True)
            usdt = usdt[affordable_mask]
            if excluded_afford:
                print(f"    资金过滤: 可用 {self.cfg.available_usdt:.1f} USDT，"
                      f"排除 {len(excluded_afford)} 个买不起的币种")
                examples = excluded_afford[:5]
                print(f"    排除示例: {', '.join(examples)}"
                      + (f" 等" if len(excluded_afford) > 5 else ""))

        # 按 USDT 成交额排序，取 top N
        usdt = usdt.sort_values("vol_usdt", ascending=False)
        candidates = usdt["inst_id"].head(self.cfg.pre_filter_top_n).tolist()

        print(f"    全量 USDT 对: {total_usdt}  →  硬过滤后: {len(candidates)}")
        return candidates

    # ------------------------------------------------------------------
    # Layer 2: 因子打分
    # ------------------------------------------------------------------

    def _compute_factors(self, candidates: list[str]) -> pd.DataFrame:
        """对每个候选拉 K 线，计算 5 个因子并加权求综合分"""
        print(f"\n  [Layer 2] 因子打分（{len(candidates)} 个候选）...")

        rows = []
        for i, inst_id in enumerate(candidates, 1):
            try:
                df = self.fetcher.get_candles(inst_id, bar=self.cfg.bar, limit=self.cfg.lookback)
                if len(df) < 50:
                    logger.debug("K 线不足: %s (%d 根)", inst_id, len(df))
                    continue

                self._candle_cache[inst_id] = df

                # 1) ADX 均值（近 30 根）
                adx_df = adx(df)
                adx_mean = adx_df["adx"].tail(30).mean()

                # 2) ATR%（ATR/close * 100）
                atr_series = atr(df)
                atr_pct = (atr_series.iloc[-1] / df["close"].iloc[-1]) * 100

                # 3) 量变比（近 20 根均量 / 全局均量）
                vol = df["vol"]
                vol_ratio = vol.tail(20).mean() / vol.mean() if vol.mean() > 0 else 1.0

                # 4) ROC（近 N 根收益率 %）
                n_roc = 20
                close = df["close"]
                roc = (close.iloc[-1] / close.iloc[-n_roc] - 1) * 100 if len(close) > n_roc else 0.0

                # 5) 带宽百分位
                bb = bollinger_bands(close)
                bw = bb["bandwidth"].dropna()
                if len(bw) > 1:
                    current_bw = bw.iloc[-1]
                    bw_pctile = (bw < current_bw).sum() / len(bw) * 100
                else:
                    bw_pctile = 50.0

                rows.append({
                    "inst_id": inst_id,
                    "adx_mean": adx_mean,
                    "atr_pct": atr_pct,
                    "vol_ratio": vol_ratio,
                    "roc": roc,
                    "bw_pctile": bw_pctile,
                })

                if i % 10 == 0:
                    print(f"    进度: {i}/{len(candidates)}")

                # 防止触发 OKX 频率限制
                time.sleep(0.15)

            except Exception as e:
                logger.warning("获取 %s 数据失败: %s", inst_id, e)
                continue

        if not rows:
            return pd.DataFrame()

        result = pd.DataFrame(rows)

        # 排名标准化（rank normalization，对加密货币厚尾分布更稳健）
        # ADX: 越高越好（趋势清晰）
        result["adx_mean_z"] = result["adx_mean"].rank(pct=True) - 0.5
        # 量变比: 越高越好（近期放量）
        result["vol_ratio_z"] = result["vol_ratio"].rank(pct=True) - 0.5
        # |ROC|: 绝对值越大越好（有波动机会，不偏多空方向）
        result["roc_z"] = result["roc"].abs().rank(pct=True) - 0.5
        # 带宽百分位: 越低越好（squeeze 蓄力，预示突破）
        result["bw_pctile_z"] = (-result["bw_pctile"]).rank(pct=True) - 0.5
        # ATR%: 中等最优 — 距中位数越近分越高
        atr_median = result["atr_pct"].median()
        result["atr_pct_z"] = (-(result["atr_pct"] - atr_median).abs()).rank(pct=True) - 0.5

        # 加权综合分
        result["score"] = (
            self.cfg.weight_adx * result["adx_mean_z"]
            + self.cfg.weight_atr_pct * result["atr_pct_z"]
            + self.cfg.weight_vol_ratio * result["vol_ratio_z"]
            + self.cfg.weight_roc * result["roc_z"]
            + self.cfg.weight_bandwidth_pctile * result["bw_pctile_z"]
        )

        result = result.sort_values("score", ascending=False).reset_index(drop=True)
        print(f"    有效候选: {len(result)}")
        return result

    # ------------------------------------------------------------------
    # Layer 3: 相关性去重
    # ------------------------------------------------------------------

    def _correlation_filter(self, scored_df: pd.DataFrame, top_n: int) -> list[str]:
        """从缓存取 close 序列，构建相关矩阵，贪心选不相关的 top N"""
        print(f"\n  [Layer 3] 相关性去重 (阈值={self.cfg.corr_threshold})...")

        ranked = scored_df["inst_id"].tolist()

        # 构建 close 收益率矩阵
        returns_dict = {}
        for inst_id in ranked:
            df = self._candle_cache.get(inst_id)
            if df is not None and len(df) > 1:
                returns_dict[inst_id] = df["close"].pct_change().dropna().values

        # 对齐长度
        if not returns_dict:
            return ranked[:top_n]

        min_len = min(len(v) for v in returns_dict.values())
        aligned = {k: v[-min_len:] for k, v in returns_dict.items()}
        ret_df = pd.DataFrame(aligned)
        corr_matrix = ret_df.corr()

        # 贪心选择：按评分排名依次加入，跳过与已选高度相关的
        selected: list[str] = []
        for inst_id in ranked:
            if inst_id not in corr_matrix.columns:
                continue
            if len(selected) >= top_n:
                break

            is_correlated = False
            for existing in selected:
                if abs(corr_matrix.loc[inst_id, existing]) >= self.cfg.corr_threshold:
                    is_correlated = True
                    logger.debug("跳过 %s（与 %s 相关性 %.2f）",
                                 inst_id, existing, corr_matrix.loc[inst_id, existing])
                    break

            if not is_correlated:
                selected.append(inst_id)

        print(f"    最终选出: {len(selected)} 个交易对")
        return selected

    # ------------------------------------------------------------------
    # 打印结果
    # ------------------------------------------------------------------

    def print_results(self, selected: list[str], scored_df: pd.DataFrame):
        """用 tabulate 打印中文评分表"""
        from tabulate import tabulate

        if scored_df.empty:
            print("\n  无评分数据")
            return

        display_cols = ["inst_id", "adx_mean", "atr_pct", "vol_ratio", "roc", "bw_pctile", "score"]
        display_df = scored_df[display_cols].copy()

        # 标记选中
        display_df["选中"] = display_df["inst_id"].apply(lambda x: "✓" if x in selected else "")

        headers = ["交易对", "ADX均值", "ATR%", "量变比", "ROC%", "带宽百分位", "综合分", "选中"]
        rows = []
        for _, r in display_df.iterrows():
            rows.append([
                r["inst_id"],
                f"{r['adx_mean']:.1f}",
                f"{r['atr_pct']:.2f}",
                f"{r['vol_ratio']:.2f}",
                f"{r['roc']:+.2f}",
                f"{r['bw_pctile']:.0f}",
                f"{r['score']:+.3f}",
                r["选中"],
            ])

        print(f"\n{'='*75}")
        print(f"  因子评分表（按综合分排序）")
        print(f"{'='*75}")
        print(tabulate(rows, headers=headers, tablefmt="simple", stralign="right"))
        print()
