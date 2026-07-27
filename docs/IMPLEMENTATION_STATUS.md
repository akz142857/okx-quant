# 生产方案实施与证据矩阵

更新时间：2026-07-27

代码实施与生产准入是两件事。下表描述当前仓库能力；需要时间、凭据或真实基础设施的
证据保持开放，详见 `RELEASE_CHECKLIST.md`。

| 阶段 | 已实现 | 自动证据 | 外部/时间门槛 |
|---|---|---|---|
| Phase 0 | golden 基线、安全默认配置、demo 隔离 | 全量 pytest | demo key 隔离核验 |
| Phase 1 | WAL journal、v1→v9 顺序迁移、Decimal 状态机、永久 clOrdId、单写者、原子 BUY 风控/预留、fills+完整对账 checkpoint 投影重建 | domain/repository/fault tests | 旧不完整 adjustment 需要真实对账 checkpoint |
| Phase 2 | order/history/fills、UNKNOWN resolver、外部订单导入、recovery gate | 响应丢失不重下测试 | OKX demo 响应证据 |
| Phase 3 | orders/balance/algo 私有 WS、重连、REST baseline、乱序幂等 | WS replay tests | 长连断网演练 |
| Phase 4 | 独立 OCO/conditional、partial-fill amend、trailing、exit lease、3 秒独立 deadline Page、emergency | protection race/lost ACK tests | attached TP/SL demo contract、真实保护 p99 |
| Phase 5 | 订单/fills/余额/algo 周期对账、差异分类、manual review | reconciliation fixtures | 人工制造交易所差异演练 |
| Phase 6 | 组合硬风控、模式/kill switch、JSON 日志、Prometheus histogram、durable SLO 日报告、告警、磁盘/inode watchdog、备份、原子 cold restore | ops tests、Bandit、OS/semantic fault artifact | 外部 Page、S3、空主机恢复 |
| Phase 7 | 组合回测、walk-forward、动态成本、压力 producer、预注册参数网格、v2 可重放 provenance、research policy/runner 双签名、shadow、签名准入 ledger | research gate tests | 连续 30 日 demo、真实研究制品与独立签名、canary |

当前本地自动门禁基线：

- 449 项测试通过；另有 1 个 TCP-bind healthz 用例因当前桌面沙箱权限未执行，Linux
  CI 必须执行；
- 核心订单状态机分支覆盖率 96.30%；
- 全仓 Ruff 规则通过；
- Bandit 高严重度/高置信度结果为零；
- 故障注入集合 184 项通过；覆盖事务中 SIGKILL、kernel socket 黑洞、SQLite
  read-only 与真实 SQLITE_FULL；
- wheel 与 sdist 构建成功。

三组独立审查进一步覆盖了交易/保护竞态、运维与密钥边界、研究准入与偏差。P0/P1
发现已补入回归，包括 HTTP 408/5xx UNKNOWN、MANUAL_REVIEW 持续冻结、partial-fill
保护替换、TRIGGERED 退出去重、启动/重连/周期/立即对账/人工恢复统一私有事件 fence、
生产日志原子初始化与不可变账户绑定、硬状态 epoch/CAS、一次性 Ed25519 双人恢复/
flatten 批准与 Page challenge、生产准入 evidence/ledger/budget 根签名、每日独立监控
观测锚、trader/watchdog/backup 进程与秘密隔离、
pending BUY 外部 watchdog、demo 证据禁止回填、连续 OOS，以及研究成本/数据/策略/
压力/组合权重 manifest 强绑定和稠密牛熊周期证明。
生产启动还使用单一 root-owned launch manifest，组合绑定实际导入源码、完整脱敏配置、
策略/bar/交易对/调度周期；首次有效窗口由 root 写入 durable deployment receipt，
相同身份重启不受短效审批/evidence 到期影响，任何身份变化都要求重新准入。
研究入口还会在数值转换前拒绝布尔型，校验 OHLCV 的有限性、正值、价格结构与
非负成交量，并从每日 benchmark/完整参数 rows 重算周期和平台，防止布尔字段、坏点
或删减参数点伪造完整市场周期。动态成本 manifest、原始数据来源和独立监控公钥指纹
也进入最终签名根。

仓库现在具备生产候选实现，但在 `RELEASE_CHECKLIST.md` 全部签署前，结论始终是
**NOT ADMITTED**，不得描述为已达到无人值守生产准入。
