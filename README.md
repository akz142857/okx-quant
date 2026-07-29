# OKX 量化交易系统

项目当前的实盘安全、回测可信度和后续建设路线，见
[项目综合评估](docs/PROJECT_EVALUATION.md)；生产升级的具体架构和实施阶段见
[生产级升级方案](docs/PRODUCTION_PLAN.md)。持续 Demo 验证的实际部署与计时流程见
[Demo / Shadow 长期验证运行手册](docs/DEMO_OPERATIONS_RUNBOOK.md)。

> 当前仓库具备生产候选内核和 Demo/Canary 准入工具，但尚未取得 72 小时 Shadow、
> 7 日 burn-in、连续 30 个完整 UTC clean day、第二故障域告警和空主机恢复等真实
> 证据，状态仍为 **NOT ADMITTED**。下方 `live` 命令不是绕过准入门禁的授权。

## 安装

需要 Python 3.12+，使用 [uv](https://docs.astral.sh/uv/) 管理依赖。

```bash
# 安装 uv（如尚未安装）
curl -LsSf https://astral.sh/uv/install.sh | sh

# 克隆项目并安装依赖
git clone <repo-url> && cd okx-quant
uv sync

# 复制配置文件并填写 API Key
cp config.yaml.example config.yaml
```

## 快速开始

```bash
# 交互模式（无参数启动向导）
uv run python main.py
```

## 命令行用法

```bash
# 查看行情
uv run python main.py ticker --inst BTC-USDT

# 策略回测
uv run python main.py backtest --inst DOGE-USDT --strategy bollinger --bar 4H --days 30

# 实盘交易 — 单币种
uv run python main.py live --inst DOGE-USDT --strategy bollinger --bar 4H --interval 10

# 实盘交易 — 多币种（逗号分隔）
uv run python main.py live --inst DOGE-USDT,PUMP-USDT --strategy ma_cross --bar 15m --interval 10

# 实盘交易 — 日志模式（不渲染仪表盘）
uv run python main.py live --inst DOGE-USDT,PUMP-USDT --strategy ma_cross --bar 15m --no-dashboard

# 查看可用交易对
uv run python main.py list-pairs

# 查看可用策略
uv run python main.py list-strategies
```

### 实盘参数

| 参数 | 说明 | 默认值 |
|---|---|---|
| `--inst` | 交易对，多个用逗号分隔 | 必填 |
| `--strategy` | 策略名称 | `ma_cross` |
| `--bar` | K 线周期 | `1H` |
| `--interval` | 轮询间隔（秒） | `60` |
| `--no-dashboard` | 禁用面板，使用日志输出 | 关 |

### 多币种架构

单币种走 `LiveTrader`，多币种自动切换为 `Supervisor + Worker` 架构：

- 每个交易对一个 Worker 线程独立运行策略；订单统一进入持久化单写者
- 共享同一个 `RiskManager`（线程安全），统一监控账户回撤
- `max_position_pct` 自动均分（如配置 0.95，2 个币种时每个 0.475）
- `max_open_positions` 自动设为币种数
- 主线程渲染多币种仪表盘，每秒刷新

### 策略说明

Bollinger — 有明确买入价位：下轨就是买入触发价。价格跌到下轨 + RSI<40 就买。

MA Cross — 没有固定买入价位。它看的是两条均线的相对位置，不是价格到某个点就买。买入触发条件是 EMA快线从下方穿越慢线（金叉），这取决于价格走势的动量，没法提前算出一个具体价格。

Dashboard 上看 差值 就行：
- 差值为负（快线 < 慢线）→ 等待金叉买入
- 差值由负转正 → 触发 BUY
- 差值为正（快线 > 慢线）→ 持仓中，等死叉卖出

简单说：差值越接近 0 且在收窄，离买入信号就越近。

### K 线周期选择

| 周期 | EMA9/21 覆盖 | Adaptive 冷却 | 信号频率 | 信号质量 | 手续费影响 |
|---|---|---|---|---|---|
| 15m | 2.25h / 5.25h | 1 小时 | 高 | 中 | 较大 |
| 30m | 4.5h / 10.5h | 2 小时 | 中偏高 | 中偏高 | 适中 |
| 1H | 9h / 21h | 4 小时 | 低 | 高 | 小 |
| 4H | 36h / 84h | 16 小时 | 很低 | 很高 | 很小 |

推荐 **15m**（配合 Adaptive 策略，轮询间隔 20~30 秒）：

- 小账户需要信号频率，1H 级别信号过于稀少，资金利用率低
- Adaptive 的 `cooldown_bars=4` 在 15m 下等于 1 小时确认才切换策略，不会频繁乱切
- Bollinger %B 和 RSI 阈值在 15m 上更容易触及，信号覆盖面好
- 选币器已筛选出高波动币种，15m 更能捕捉这些波动

## 配置说明

复制 `config.yaml.example` 为 `config.yaml` 并填写：

```bash
cp config.yaml.example config.yaml
```

> **`config.yaml` 包含 API Key 等敏感信息，已在 `.gitignore` 中排除，请勿提交。**

### OKX API (`okx`)

| 参数 | 说明 | 默认值 |
|---|---|---|
| `api_key` | OKX API Key | 必填 |
| `secret_key` | OKX Secret Key | 必填 |
| `passphrase` | OKX Passphrase | 必填 |
| `simulated` | `true` 模拟盘 / `false` 实盘 | `true` |
| `base_url` | API 地址 | `https://openapi.okx.com` |
| `proxy` | HTTP 代理（可选，留空直连） | 空 |
| `timeout` | 单次 HTTP 请求超时（秒） | `15` |
| `max_retries` | 连接失败或限速后的重试次数 | `3` |

### 风控 (`risk`)

| 参数 | 说明 | 默认值 |
|---|---|---|
| `max_position_pct` | 单笔最大仓位占总资产比例 | `0.5` (50%) |
| `max_drawdown_pct` | 最大回撤触发停止开新仓（已有仓位仍可退出） | `0.15` (15%) |
| `stop_loss_pct` | 默认止损比例 | `0.02` (2%) |
| `take_profit_pct` | 默认止盈比例 | `0.04` (4%) |
| `max_open_positions` | 最大同时持仓数 | `1` |
| `min_order_usdt` | 最小下单金额 (USDT) | `1.0` |

### 日志 (`logging`)

| 参数 | 说明 | 默认值 |
|---|---|---|
| `level` | 日志级别 (`DEBUG` / `INFO` / `WARNING` / `ERROR`) | `INFO` |
| `file` | 日志文件路径 | `logs/quant.log` |

### 回测 (`backtest`)

| 参数 | 说明 | 默认值 |
|---|---|---|
| `initial_capital` | 初始资金 (USDT) | `10000.0` |
| `fee_rate` | 手续费率 | `0.001` (0.1%) |
| `slippage` | 滑点 | `0.0005` (0.05%) |

### LLM 配置 (`llm` / `llm_deep`)

`llm` 用于 AI 策略的分析模型（轻量），`llm_deep` 用于多 Agent 辩论+决策（强力模型）。

| 参数 | 说明 | 默认值 |
|---|---|---|
| `provider` | 模型提供商 (`openai` / `claude` / `deepseek`) | `openai` |
| `api_key` | API Key | 必填 |
| `model` | 模型名称，留空用提供商默认 | — |
| `base_url` | API 地址，留空用提供商默认 | — |
| `temperature` | 生成温度 | `0.3` |
| `max_tokens` | 最大 token 数 | `1024` / `2048` |
| `timeout` | 请求超时（秒） | `30` / `60` |

### 多 Agent (`multi_agent`)

| 参数 | 说明 | 默认值 |
|---|---|---|
| `debate_rounds` | 多空辩论轮数 | `2` |
| `confidence_threshold` | 低于此置信度 → HOLD | `0.6` |

### 因子选币器 (`screener`)

| 参数 | 说明 | 默认值 |
|---|---|---|
| `min_vol_24h_usdt` | 最小 24H 成交额 (USDT) | `500000` |
| `min_listing_days` | 最少上线天数 | `90` |
| `pre_filter_top_n` | 硬过滤后保留 top N | `30` |
| `bar` | K 线周期 | `4H` |
| `lookback` | 回看 K 线根数 | `100` |
| `corr_threshold` | 相关性去重阈值 | `0.85` |

权重参数（总和建议为 1.0）：`weight_adx` (0.30)、`weight_atr_pct` (0.20)、`weight_vol_ratio` (0.15)、`weight_roc` (0.15)、`weight_bandwidth_pctile` (0.20)。

### 新闻 (`news`)

| 参数 | 说明 | 默认值 |
|---|---|---|
| `auth_token` | CryptoPanic API token（可选，不填也能用） | 空 |


## 交互模式

无参数启动进入向导菜单：

```
$ uv run python main.py

OKX 量化交易系统 v1.0.0

[1] 查看行情
[2] 策略回测
[3] 实盘交易
[4] 因子选币
[5] 查看可用交易对
[6] 查看可用策略
[q] 退出

请选择 [1-6/q]:
```

### 实盘交易 + 自动选币示例

选择「实盘交易」后可开启自动选币，系统通过三层漏斗筛选最优交易对：

```
— 实盘交易 —

是否自动选币？ [n] (y/n): y
选出 top N 交易对 [5]: 2

选择策略 [1-7，默认 1]: 7    # adaptive 自适应策略
K 线周期 [1H]: 15m
轮询间隔（秒） [60]: 20
```

因子选币器执行三层筛选：

1. **硬过滤** — 按成交额、上线天数等条件初筛（291 → 30）
2. **因子打分** — ADX、ATR%、量变比、ROC、布林带宽 五因子加权评分
3. **相关性去重** — 剔除高度相关的币种，保留多样性

```
因子评分表（按综合分排序）
      交易对    ADX均值   ATR%   量变比   ROC%   带宽百分位   综合分   选中
   TRX-USDT     26.9    0.1    1.37   -0.38       99    1.089    ✓
SAHARA-USDT     27.1    1.97   1.09    2.37       64    0.665    ✓
  AAVE-USDT     26.9    0.75   0.92    0.61       41    0.603
   SOL-USDT     15.1    0.82   1.18    2.32       55    0.371
          ...

选中交易对: TRX-USDT, SAHARA-USDT
确认使用以上交易对开始交易? (y/N):
```

---

## 生产部署与运行

仓库包含生产候选内核，但不因代码测试通过而自动取得实盘准入。所有环境必须先经过
`local fake → CI → OKX demo → shadow → canary → limited production`，并满足连续
30 日 demo 与人工安全证据。

不使用真实资金时，可以先生成绑定当前源码和全部测试清单的离线证据：

```bash
uv run python scripts/non_live_validation.py \
  --allow-dirty \
  --output non-live-validation.json
```

该报告明确标记 `production_admissible=false`，不会冒充真实 Demo 或生产准入。完整的
离线、历史回放、OKX Demo、Shadow 和预生产验证路径见
[非实盘验证指南](docs/NON_LIVE_VALIDATION.md)。

关键资料：

- [实施与证据矩阵](docs/IMPLEMENTATION_STATUS.md)
- [非实盘验证指南](docs/NON_LIVE_VALIDATION.md)
- [Demo / Shadow 持续运行计划](docs/DEMO_SHADOW_VALIDATION_PLAN.md)
- [生产运行手册](docs/RUNBOOK.md)
- [生产准入清单](docs/RELEASE_CHECKLIST.md)
- [安全模型](docs/SECURITY.md)
- [生产升级方案](docs/PRODUCTION_PLAN.md)

生产使用彼此隔离的 `okxquant-trader`、`okxquant-watchdog`、`okxquant-backup`
非 root 身份，以及 `/etc/okx-quant` 配置、`/var/lib/okx-quant` 交易状态和
`/var/log/okx-quant` 日志。模板位于 `deploy/`；systemd unit 已配置
`ProtectSystem=strict`、`NoNewPrivileges`、资源上限、独立 watchdog、5 分钟加密
异地归档，并在启动 trader 前验证现有 v1 证据与独立风险审批签名。多角色评审已确认
v1 不能启动正式 30 日计时；必须先完成持续运行计划中的 SLO/Gate v2、Probe saga、
三环境能力隔离和 Demo→Canary identity transition。

常用安全命令：

```bash
okx-quant --config /etc/okx-quant/config.yaml production-status
okx-quant --config /etc/okx-quant/config.yaml audit-order <clOrdId>
okx-quant --config /etc/okx-quant/config.yaml halt-entries --actor <operator>
okx-quant --config /etc/okx-quant/config.yaml reconcile-now --wait 30
okx-quant --config /etc/okx-quant/config.yaml backup-now
```

全新生产账户必须先按运行手册执行一次 `init-journal`；正常 `live` 不会在数据库
缺失或为空时创建新账本。解除 `HALTED` 需要 operator 生成短效请求、独立风险审批人
用离线 Ed25519 私钥签名，再提交一次性批准文件；交易主机仅保存公钥。

Canary 准入采用不可跳步的两阶段 systemd 流程。第一阶段显式运行全部 12 路
collector → signer；独立 IAM issuer 先把原生签名 STS receipt 放入
`/run/okx-quant-canary-iam/<00..11>.json`，signer 再把实际读取的精确 bytes 固化到
对应 signed 目录。对象存储发布角色随后把本轮 `source.json` 上传到 inventory 冻结的
Object Lock locator/KMS policy，取得真实 `versionId`，并把 exact version 同时写入
每路 WORM 环境文件和 root-owned capability manifest。上传动作不由 collector、
signer 或 capability authority 代做。

第二阶段才启动 `okx-quant-canary-capability@<hard-epoch>.service`。它只要求 12 路
WORM exact-version GET 与独立 deployment verifier，不会直接或间接重启
collector/signer；`ExecStartPre --check-inputs-only` 先检查全部 manifest 输入存在且
安全，最终 builder 再执行密码学与内容验证。WORM、deployment 和 capability 输出
create-if-absent；新 hard epoch 必须停止旧的 stage-2 unit、使用全新的空证据目录，
并在并行 WORM 回读后的 30 秒 freshness 窗口内构建 capability。直接跳过阶段 1、
复用旧 version/receipt 或在活动 epoch 内覆盖文件都会 fail closed。

密码学验证仍是最终边界：capability manifest 必须精确列出 12 份 source、12 份原生
STS receipt、12 份独立签名 WORM 回读和一份覆盖 12 路 unit/权限/可执行文件哈希的部署
证明；缺一项或多一项都失败。capability、IAM、WORM 回读、deployment verifier 使用
四把互不相同且不与 producer/审批复用的密钥。OKX collector 从实际 systemd credential
动态生成 V5 签名并校验真实 API key 指纹；备份证明执行 archive 与 manifest 两次精确
version GET，并对恢复出的 SQLite 运行 `PRAGMA integrity_check`。
WORM verifier 同样不接受静态 Authorization：它从独立 systemd credentials 读取
AWS access key、secret 和短效 session token，按冻结的 S3 region/origin/object/version
动态生成 SigV4 `x-amz-date`、空 payload SHA 与 Authorization；receipt 只记录 access
key 指纹，capability 必须将其与 inventory 冻结值精确匹配，secret/token 不进入证据。
每个 collector 实例必须在
`/etc/okx-quant/canary-producers/credentials/<00..11>/` 提供 unit 声明的四个
credential 文件；只给需要 OKX V5 的隔离实例填入真实三元凭据，其他实例使用不含秘密
的占位值，外部源令牌仅写入 `source-authorization`。collector request 中的 credential
名称也被冻结进 request hash，不能在启动时改指向其他文件。

通过 Gate 只会在 root-owned、不可组/其他写的 admission 目录中建立短效 reservation；
审批必须绑定该 bundle，activate 在同一个 companion `flock` 事务锁下只消费一次。
并发 Gate/activate 不能重复预留或消费同一 capability。全部 receipt 还必须绑定同一
transition、startup nonce、hard epoch、boot/host identity，并满足 30 秒新鲜度窗口，
所以手工启动 unit 或遗留旧文件不能绕过验证。没有真实外部 API、STS、Object Lock 和
主机 systemd 产出的这些证据时，状态保持 `OPEN`，不得宣称已获生产准入。

`flatten-and-cancel` 是破坏性资金操作，必须先生成绑定具体交易对集合的短效请求，
由独立风险审批人签名，再使用账户绑定的精确确认词提交。禁止通过删除状态文件、
覆盖交易数据库或重复提交 UNKNOWN 订单来“恢复”。

---

## 量化策略验证流程

### 工具链

| 脚本 | 用途 |
|---|---|
| `scripts/backtest_grid.py` | 网格化回测 —— N 策略 × M 币 × K 周期 |
| `scripts/backtest_report.py` | 结果汇总排序（按 raw Sharpe） |
| `scripts/backtest_analyze_alpha.py` | **HODL-adjusted 分析**，按 alpha_sharpe 排序 |
| `scripts/param_sweep.py` | 参数敏感性扫描，区分真 edge vs 过拟合 |
| `scripts/summary.sh` | 实盘 bot 状态汇总 |
| `scripts/verify_deploy.sh` | 部署后一键 health check |

### Phase 1：网格回测

```bash
# 默认：6 策略 × 20 币 × 3 周期 × 2 年 = 360 组合
uv run python scripts/backtest_grid.py

# 自定义
uv run python scripts/backtest_grid.py \
  --strategies ma_cross,bollinger,ensemble \
  --instruments BTC-USDT,ETH-USDT,SOL-USDT \
  --bars 1H,4H \
  --days 730 \
  --outdir backtest_results \
  --parallel 8

# 续跑（跳过已完成组合）
uv run python scripts/backtest_grid.py --resume

# 只预览，不执行
uv run python scripts/backtest_grid.py --dry-run
```

K 线缓存到 `backtest_results/candles/*.parquet`，避免重复下载。

### Phase 1 分析（必须用 HODL-adjusted）

```bash
uv run python scripts/backtest_analyze_alpha.py \
  --results backtest_results/results.csv \
  --candles backtest_results/candles \
  --min-alpha-sharpe 0.3 \
  --min-trades 20
```

**关键指标**：`alpha_sharpe = strategy_sharpe - HODL_sharpe`。

**只有 alpha_sharpe ≥ 0.3 且 total_return > 0 的组合才是真 edge**。单纯 raw Sharpe 正不算数 —— 大牛市里躺平持币就正 Sharpe，那是 beta 不是 alpha。

### Phase 1.5：参数敏感性扫描

```bash
# 对 Phase 1 筛出的候选做参数扫描
uv run python scripts/param_sweep.py \
  --strategy ma_cross --inst AVAX-USDT --bar 4H \
  --days 730 \
  --cache-dirs backtest_results/candles

# 从 grid 结果自动取 Top N
uv run python scripts/param_sweep.py --from-grid --top 5 --min-sharpe 0.3
```

输出标记每个参数为 `robust`（扫描均正）或 `fragile`（多数崩盘）。fragile 的不要进实盘。

### Phase 2：生成生产候选

参数扫描只能生成候选，不能直接批准实盘。候选还必须依次通过 walk-forward、组合共享
现金回测、压力测试、OKX demo、shadow、连续 30 日证据、canary 与
[`docs/RELEASE_CHECKLIST.md`](docs/RELEASE_CHECKLIST.md) 人工审批。

---

## 故障排查

### Bot 跑着跑着亏了很多

1. 看 `summary.sh` 的 `journal 错误` 计数 —— 有无异常
2. 看最近 `[下单]` 事件 —— 是正常止损还是异常执行
3. 看 OKX 网页订单历史，对照 journal 时间戳
4. **不要慌着手动干预** —— 策略可能在正常的回撤期；`max_drawdown_pct=0.15` 触发后会自动停盘

### 卖单反复失败 (OKX 51008)

现象：`[下单] 卖出失败 ... available CFX balance is insufficient`

根因：OKX 现货 market buy 扣币种手续费后，实际到账 < 下单量。

**已修复**（commit `85492a0`）：`sell()` 查交易所实际 available，取 `min(pos.size, available)`。

如果还发生，说明历史 state 文件里记的 size 过大。清除：

```bash
ssh root@64.23.157.26 'systemctl stop okx-quant && rm /opt/okx-quant/state/state_<INST>.json && systemctl start okx-quant'
```

### 内存超过 600M 被 systemd 杀

1GB droplet 上 LLM 策略容易吃内存。`MemoryMax=600M` 会 OOM-kill。对策：

- 换非 LLM 策略（`ma_cross` / `bollinger` / `adaptive`）
- 或升级 droplet 到 2GB/2vCPU
- 或调低 `max_total_tokens` 限制 LLM 批量

### 实盘确认卡住（非交互环境）

如果改了 `simulated: false` 但 bot 启动卡在 `输入 'I UNDERSTAND'` 提示：

```bash
# env 里必须有这行（已默认有）
ssh root@64.23.157.26 'grep OKX_LIVE_CONFIRMED /etc/okx-quant.env'
# 若无，加上：
ssh root@64.23.157.26 'echo "OKX_LIVE_CONFIRMED=1" >> /etc/okx-quant.env && systemctl restart okx-quant'
```

### 状态文件损坏

症状：启动后 `[状态] 加载失败` 警告。

```bash
ssh root@64.23.157.26 'systemctl stop okx-quant && rm /opt/okx-quant/state/*.json && systemctl start okx-quant'
```

Bot 会用交易所实际余额重建 position 记录。

### 代码拉取后 bot 起不来

```bash
ssh root@64.23.157.26 'cd /opt/okx-quant && /root/.local/bin/uv sync 2>&1 | tail -5'
# 如果依赖装失败：
ssh root@64.23.157.26 'cd /opt/okx-quant && /root/.local/bin/uv lock --upgrade && /root/.local/bin/uv sync'
```

---

## 项目结构速查

```
okx_quant/
├── client/rest.py           OKX V5 REST（带限流重试、HMAC 签名）
├── client/websocket.py      WS 客户端（已接入 production runtime）
├── exchange/                抽象层：Exchange Protocol + OKXExchange/FakeExchange
├── data/market.py           K 线/Ticker 拉取（带缓存 + 分页）
├── data/news.py             CryptoPanic 新闻（可选）
├── data/screener.py         因子选币器
├── indicators/              SMA/EMA/MACD/BBands/ATR/ADX/RSI（含回测预计算缓存）
├── strategy/                8 策略：ma_cross / rsi_mean / bollinger / adaptive /
│                            trend_momentum / llm / ensemble / multi_agent
├── backtest/engine.py       回测引擎（next-bar open 成交，无 lookahead）
├── risk/manager.py          风控（线程安全，止损/回撤/自动恢复）
├── llm/client.py            OpenAI/Claude/DeepSeek 统一客户端
├── agentic/                 多 Agent pipeline（4 分析师 + Bull/Bear 辩论）
├── trading/executor.py      LiveTrader（tick 循环）
├── trading/orders.py        OrderExecutor（下单+冷却+幽灵清理）
├── trading/position_monitor.py  SL/TP + trailing stop
├── trading/account.py       余额缓存
├── trading/decision_log.py  决策 CSV
├── trading/state.py         状态持久化（原子 JSON 写）
├── trading/supervisor.py    多币 Supervisor
├── trading/position_restore.py  启动时恢复已有持仓（过滤粉尘）
├── utils/timeout.py         硬超时包装（保护主循环不被 LLM 阻塞）
└── config.py                ${VAR} env 变量展开

scripts/
├── backtest_grid.py         Phase 1 网格回测
├── backtest_report.py       raw Sharpe 排序
├── backtest_analyze_alpha.py  HODL-adjusted 分析（推荐）
├── param_sweep.py           参数敏感性扫描
├── summary.sh               生产状态汇总
└── verify_deploy.sh         部署 health check
```

测试数量和覆盖率以 CI 与
[`docs/IMPLEMENTATION_STATUS.md`](docs/IMPLEMENTATION_STATUS.md) 的最新门禁结果为准，
覆盖指标、回测、风控、持久化订单、恢复、保护、运维与安全。

```bash
uv run pytest -q              # 全量
uv run pytest tests/test_order_executor.py -v  # 单文件
```
