# OKX 量化交易系统使用手册

更新时间：2026-07-31

本文面向第一次使用本项目的开发者和运维人员，覆盖本机安装、行情与回测、OKX
模拟盘账号验证、交易事实账本、Web Dashboard，以及正式 Demo Shadow / Active
验证的入口。

> **安全状态：NOT ADMITTED**
>
> 当前代码和工具已经具备生产候选能力，但尚未取得 72 小时 Shadow、7 日 Active、
> 6 项核心故障演练、不可变证据回读和双人 Canary 审批。任何 `live` 命令都不代表
> 已获准连接真实资金账户。

## 1. 使用场景

| 场景 | 是否连接 OKX | 是否下单 | 推荐环境 |
|---|---:|---:|---|
| 合成 Dashboard 预览 | 否 | 否 | macOS / Linux 本机 |
| 行情、选币和回测 | 仅公共接口 | 否 | macOS / Linux 本机 |
| Demo API 鉴权诊断 | 是，模拟盘 | 否 | 本机 |
| Demo API 交易诊断 | 是，模拟盘 | 是，约 1 USDT | 本机，人工监督 |
| 正式 Shadow | 是，独立只读账号 | 否 | 通过 Gate A preflight 的 Linux |
| 正式 Active | 是，独立 Demo 交易账号 | 每日限定 probe | 通过 Gate A preflight 的 Linux |
| 真实资金 Canary | 是 | 是 | Gate A、Gate C 全部批准后 |

如果只是想快速查看系统效果，从“[4. 本机快速体验](#4-本机快速体验)”开始。

## 2. 环境准备

### 2.1 前置要求

- Python 3.12 或更高版本；
- `uv`；
- Git；
- 访问 OKX 公共 API 的网络；
- 若验证账号，准备 OKX Demo API Key。

进入项目目录并安装锁定依赖：

```bash
cd /path/to/okx-quant
uv sync --frozen
```

如果 `.venv` 曾指向已删除的 Python，`uv` 会自动重建它。安装完成后可验证：

```bash
./.venv/bin/python main.py --help
./.venv/bin/python scripts/test_api.py --help
```

### 2.2 配置文件

创建个人配置：

```bash
cp config.yaml.example config.yaml
```

`config.yaml` 默认使用 OKX 模拟盘，并将本地事实账本写到
`state/demo/trading.db`。不要把个人配置或密钥提交到 Git。

配置中的 `${VAR}` 和 `${VAR:-default}` 会从环境变量展开。建议把密钥放在独立文件：

```dotenv
OKX_API_KEY=replace-with-demo-api-key
OKX_SECRET_KEY=replace-with-demo-secret
OKX_PASSPHRASE=replace-with-demo-passphrase
```

例如保存为 `$HOME/.okx-demo.env`，然后收紧权限：

```bash
chmod 600 "$HOME/.okx-demo.env"
```

密钥文件只能包含 `KEY=VALUE`，不要加入 `export`、shell 命令或引号拼接。不要把真实
密钥粘贴到聊天、Issue、日志或截图中。

## 3. OKX Demo 账号要求

本地交易诊断至少需要一个 OKX Demo API Key：

- 开启 Read；
- 只有执行 `--trade` 时才开启 Trade；
- 必须关闭 Withdraw；
- 确认创建的是模拟盘 Key，而非真实资金账户 Key；
- 推荐设置 IP 白名单。

正式 Gate A 需要两个相互隔离的 Demo 账号或子账号：

| 角色 | Key 权限 | 用途 |
|---|---|---|
| Shadow | 仅 Read | 连续 72 小时观察、行情、账户和对账 |
| Active | Read + Trade | 连续 7 日、每日一个 5–10 USDT durable probe |

两者不得共享 API Key、账号 UID、数据库、Unix 用户、network namespace、备份目录或
metrics 端口。正式要求见
[Demo / Shadow 长期验证运行手册](./DEMO_OPERATIONS_RUNBOOK.md)。

## 4. 本机快速体验

### 4.1 查看完整 Dashboard 效果

合成预览不读取密钥、不连接 OKX，也不会下单：

```bash
./.venv/bin/python scripts/dashboard_preview.py --port 9181
```

浏览器打开：

```text
http://127.0.0.1:9181
```

页面顶部会显示 `SYNTHETIC PREVIEW`。预览账本位于系统临时目录，按 `Ctrl+C`
退出后自动删除。

### 4.2 查看公开行情

```bash
./.venv/bin/python main.py \
  --config config.yaml \
  ticker \
  --inst BTC-USDT
```

全局参数 `--config`、`--env-file`、`--log-level` 必须放在子命令之前。

### 4.3 查看可用交易对和策略

```bash
./.venv/bin/python main.py --config config.yaml list-pairs
./.venv/bin/python main.py --config config.yaml list-strategies
```

### 4.4 运行回测

```bash
./.venv/bin/python main.py \
  --config config.yaml \
  backtest \
  --inst DOGE-USDT \
  --strategy bollinger \
  --bar 4H \
  --days 30
```

导出权益曲线：

```bash
./.venv/bin/python main.py \
  --config config.yaml \
  backtest \
  --inst DOGE-USDT \
  --strategy bollinger \
  --bar 4H \
  --days 30 \
  --export-csv evidence/doge-backtest.csv
```

回测结果不等于未来收益，也不能替代 Demo soak、滑点验证和风险审批。

### 4.5 运行选币器

```bash
./.venv/bin/python main.py \
  --config config.yaml \
  screen \
  --top 10 \
  --bar 4H \
  --min-vol 500000
```

可用 `--max-price` 增加单价过滤；`0` 表示不过滤。

## 5. 验证 Demo 测试账号

先只验证网络和鉴权，不下单：

```bash
./.venv/bin/python scripts/test_api.py \
  --config config.yaml \
  --env-file "$HOME/.okx-demo.env" \
  --inst DOGE-USDT
```

预期依次通过：

1. 服务器时间、最新价和 K 线；
2. 账户余额；
3. 未成交订单查询；
4. 汇总显示网络连通和 API 鉴权通过。

确认输出中的“当前模式”为“模拟盘”后，才可执行约 1 USDT 的买入和卖出诊断：

```bash
./.venv/bin/python scripts/test_api.py \
  --config config.yaml \
  --env-file "$HOME/.okx-demo.env" \
  --trade \
  --inst DOGE-USDT
```

该脚本会等待买单成交，再按实际可卖余额和手续费结果清理。执行后仍应登录 OKX Demo
人工确认：

- 没有遗留现货余额；
- 没有普通挂单；
- 没有算法单或保护单；
- 账户总权益变化仅为预期的模拟手续费和滑点。

若脚本报告 cleanup 失败，不要连续重跑；先在模拟盘界面手工取消订单或平仓，并记录
失败信息。

## 6. 交易事实账本

Dashboard 读取 SQLite 事实账本。全新的本地环境没有
`state/demo/trading.db` 是正常现象。

### 6.1 初始化本地 Demo 账本

仅对一个从未使用过的新路径执行一次：

```bash
./.venv/bin/python main.py \
  --config config.yaml \
  init-journal \
  --actor local-operator \
  --confirm "INIT demo"
```

初始化会创建数据库并以 `HALTED` 状态启动。`HALTED` 是安全默认值，不是故障。

不要对已有账本反复执行初始化，也不要删除或覆盖账本来消除告警。已有账本包含订单
事实、状态迁移和审计链，应通过备份、对账和审批流程处理。

### 6.2 查看账本状态

```bash
./.venv/bin/python main.py \
  --config config.yaml \
  --env-file "$HOME/.okx-demo.env" \
  production-status
```

如果只是初始化了账本、没有受控运行时写入快照，Dashboard 显示零权益、零持仓和
`HALTED` 属于预期现象。

### 6.3 手工备份

```bash
./.venv/bin/python main.py \
  --config config.yaml \
  backup-now
```

也可用 `--destination` 指定目标文件。正式环境还必须完成异地不可变存储和
exact-version 回读；本地 SQLite 复制件不能代替正式证据。

## 7. Web Dashboard

Dashboard 是只读观察面：

- 读取 SQLite 事实账本，不直接查询 OKX；
- 不加载 API Key；
- 不提供下单、撤单、恢复开仓等写操作；
- 默认每 5 秒刷新；
- 展示运行模式、权益趋势、持仓保护、订单事实和系统事件；
- 强制绑定回环地址，不应直接暴露到公网。

启动真实账本 Dashboard：

```bash
./.venv/bin/python -m okx_quant.web_dashboard.server \
  --database state/demo/trading.db \
  --host 127.0.0.1 \
  --port 9180
```

然后访问 `http://127.0.0.1:9180`。

执行过 `uv sync` 后，也可以使用控制台入口：

```bash
uv run okx-quant-dashboard \
  --database state/demo/trading.db \
  --host 127.0.0.1 \
  --port 9180
```

如果入口提示 `No such file or directory`，优先重新执行 `uv sync --frozen`，或直接
使用上面的 `python -m` 形式。

远程查看 Linux 主机时使用 SSH 端口转发：

```bash
ssh -L 9180:127.0.0.1:9180 operator@linux-host
```

然后在本机访问 `http://127.0.0.1:9180`。不要将服务绑定到 `0.0.0.0`。

## 8. 正式 Demo Shadow / Active

本机 API 诊断和合成预览不计入正式准入证据。正式 Gate A 必须在目标 Linux 主机
完成，执行顺序如下：

1. 冻结 clean commit、lockfile、源码清单、配置摘要和解释器身份；
2. Linux CI 全绿，关键测试不得跳过；
3. 创建相互隔离的 Shadow 与 Active Demo 账号和 Key；
4. 安装独立 systemd unit、Unix UID、目录、端口和 network namespace；
5. 运行 Gate A live preflight；
6. 使用当前冻结候选重新完成 Demo contract；
7. Shadow 连续运行 72 小时；
8. Active 连续运行 7 日，每日一个限定 probe；
9. 完成 SIGTERM、SIGKILL、WS 重连、REST unknown、external fill、
   protection cancel 六项故障演练；
10. 将证据写入不可变存储并按 exact version 独立回读；
11. 由不同的 operator 和 risk approver 双签 Gate C Canary。

准确命令、部署目录、签名证据和验收条件以以下文档为准：

- [Gate A 执行清单](./GATE_A_EXECUTION_CHECKLIST.md)
- [Demo / Shadow 长期验证运行手册](./DEMO_OPERATIONS_RUNBOOK.md)
- [非实盘验证说明](./NON_LIVE_VALIDATION.md)
- [安全说明](./SECURITY.md)

不要在 macOS 直接运行正式 `live` 来代替 Gate A。正式运行时会核对 release、
preflight receipt、Unix UID、systemd cgroup、network namespace 和完整启动参数；
身份不一致时应当 fail closed。

## 9. 日常运维命令

以下命令面向已经初始化并按要求部署的运行时。

查看状态：

```bash
./.venv/bin/python main.py --config config.yaml production-status
```

按客户端订单号审计：

```bash
./.venv/bin/python main.py \
  --config config.yaml \
  audit-order CLIENT_ORDER_ID
```

请求立即对账：

```bash
./.venv/bin/python main.py \
  --config config.yaml \
  reconcile-now \
  --wait 30
```

停止新开仓：

```bash
./.venv/bin/python main.py \
  --config config.yaml \
  halt-entries \
  --actor operator-name \
  --wait 30
```

恢复开仓不是一个单人开关。必须先生成有时效的请求、取得独立审批，再执行恢复：

```bash
./.venv/bin/python main.py \
  --config config.yaml \
  resume-request \
  --actor operator-name \
  --expires-in 900 \
  --output /secure-transfer/resume-request.json
```

审批和恢复的完整流程见 [生产运行手册](./RUNBOOK.md)。不得伪造审批文件，也不要为
了让界面变绿而绕过 `HALTED`。

## 10. 停止与恢复

本机前台命令使用 `Ctrl+C` 正常停止。正式 Linux 服务使用对应 systemd unit：

```bash
sudo systemctl stop okx-quant-demo-shadow.service
sudo systemctl stop okx-quant-demo-active.service
```

停止进程不代表订单已撤销或仓位已平。停止后应核对：

- OKX 普通挂单与算法单；
- 当前仓位和可用余额；
- 事实账本中的 UNKNOWN 或未终结订单；
- 最后一次 reconciliation；
- heartbeat、告警和备份状态。

遇到超时或结果未知时，先按客户端订单号查询和对账，不要盲目重复下单。

## 11. 常见问题

### 11.1 `okx-quant-dashboard: No such file or directory`

当前虚拟环境没有安装最新项目入口：

```bash
uv sync --frozen
```

也可以使用稳定的模块入口：

```bash
./.venv/bin/python -m okx_quant.web_dashboard.server \
  --database state/demo/trading.db
```

### 11.2 `trading.db` 不存在

如果只是看效果，运行 `scripts/dashboard_preview.py`。如果需要一个新的本地 Demo
账本，按“[6.1 初始化本地 Demo 账本](#61-初始化本地-demo-账本)”执行一次
`init-journal`。正式 Linux 环境不要用本地示例身份初始化。

### 11.3 `Address already in use`

先确认占用端口的进程：

```bash
lsof -nP -iTCP:9181 -sTCP:LISTEN
```

如果它就是已启动的 Dashboard，直接访问对应地址；否则换一个端口，例如：

```bash
./.venv/bin/python scripts/dashboard_preview.py --port 9182
```

不要在未确认进程身份时直接 `kill -9`。

### 11.4 Dashboard 全是零或显示 `HALTED`

Dashboard 不从 OKX 即时拉取数据。空账本或仅初始化的账本没有权益快照，因此全零是
正常的；`HALTED` 是初始化后的安全状态。要看完整 UI，请使用合成预览。要看正式
交易事实，需要受控 Linux 运行时持续写入账本。

### 11.5 API 鉴权失败

检查：

- Key 是否属于 OKX Demo；
- `config.yaml` 中 `okx.simulated` 是否为 `true`；
- API Key、Secret 和 Passphrase 是否对应同一个 Key；
- Key 权限和 IP 白名单；
- 本机时钟偏差；
- `--env-file` 路径是否正确。

不要通过打印完整环境变量来排查密钥。

### 11.6 卖出提示余额不足

先停止重试，在 OKX Demo 页面检查实际成交、手续费、可用余额、挂单和算法单。当前
诊断脚本会按成交后的实际可用余额清理，但交易所精度、费用或短暂同步延迟仍可能
导致人工清理成为必要步骤。

### 11.7 配置提示备份间隔无效

`production.backup_interval_s` 必须在 `(0, 60]` 秒。当前
`config.yaml.example` 使用 `60`；旧的个人配置若仍为 `300`，请改为 `60`。

## 12. 开发与发布前检查

提交代码前运行：

```bash
uv sync --frozen
uv run ruff check .
uv run pytest -q
uv run python scripts/non_live_validation.py \
  --output evidence/non-live-validation.json
```

`non-live-validation.json` 保持 `production_admissible=false` 是预期结果：它只证明
离线路径可重复，不能替代真实 OKX Demo、Linux 部署、时间累积、外部告警、不可变
存储回读或人工审批。

进一步阅读：

- [README](../README.md)
- [生产运行手册](./RUNBOOK.md)
- [发布检查清单](./RELEASE_CHECKLIST.md)
- [项目综合评估](./PROJECT_EVALUATION.md)
