# 生产方案实施与证据矩阵

更新时间：2026-07-28

代码实施与生产准入是两件事。下表描述当前仓库能力；需要时间、凭据或真实基础设施的
证据保持开放，详见 `RELEASE_CHECKLIST.md`。

| 阶段 | 已实现 | 自动证据 | 外部/时间门槛 |
|---|---|---|---|
| Phase 0 | golden 基线、安全默认配置、demo 隔离 | 全量 pytest | demo key 隔离核验 |
| Phase 1 | WAL journal、v1→v11 顺序迁移、Decimal 状态机、永久 clOrdId、单写者、原子 BUY 风控/预留、fills+完整对账 checkpoint 投影重建 | domain/repository/fault tests | 旧不完整 adjustment 需要真实对账 checkpoint |
| Phase 2 | order/history/fills、UNKNOWN resolver、外部订单导入、recovery gate | 响应丢失不重下测试 | OKX demo 响应证据 |
| Phase 3 | orders/balance/algo 私有 WS、重连、REST baseline、乱序幂等 | WS replay tests | 长连断网演练 |
| Phase 4 | 独立 OCO/conditional、partial-fill amend、trailing、exit lease、3 秒独立 deadline Page、emergency | protection race/lost ACK tests；2026-07-28 交互式 Demo 已验证独立 OCO 与 attached TP/SL | release-bound Demo v2 证据、持续运行保护关联完整率/p95/max |
| Phase 5 | 订单/fills/余额/algo 周期对账、差异分类、manual review | reconciliation fixtures | 人工制造交易所差异演练 |
| Phase 6 | 组合硬风控、kill switch、Prometheus/Grafana、外部 synthetic、durable provider/human ACK、资源采样、SLO v2、持续一致性备份和 exact restore、KMS/Object Lock 回读、原子 cold restore；backup 只发签名回执；外部监控核对 endpoint 实际 account/unit/epoch；REST 写在限速后重验协调租约；未保护仓位 watchdog 无网络 I/O | ops/SLO/backup/monitor/alert-control/transport-race tests、Bandit、OS/semantic fault artifact | 第二故障域部署与告警演练；exchange-side fencing/STONITH；真实 local/offsite RPO≤5m；月度空主机 RTO<30m |
| Phase 7 | 组合回测、walk-forward、动态成本、压力 producer、预注册研究、durable probe saga capability、epoch 前锁定的 30 日每日精确一 slot、4×2×2 联合分层 schedule、精确 DONE probe residual 集合的 Student-t 单侧 95% UCB、双签 soak epoch、原始 SQLite/外部对象 exact-version 语义重建、不可变 ledger、Canary 12 路 collector/signer/systemd/WORM/deployment-attestation 协议与 hard-epoch 一次性 activation；缺真实 external evidence 时固定 fail closed | research/SLO/probe/canary/gate tests | 72h Shadow、7d burn-in、最终 freeze chaos、连续 30 个 clean day、13 个 Stage-C 场景执行器、12 路 Canary 真实部署/IAM/STS/Object Lock 证据、真实研究制品与独立签名 |

当前本地自动门禁基线：

- 全部测试文件已纳入不可漏项的七组非实盘验证 inventory；Linux CI 必须全绿；
- 当前 macOS 全量回归为 754 passed、3 skipped，Ruff 全绿；目标 Linux CI 仍必须在冻结提交上
  独立全量通过，不能把本地结果替代发布 CI；
- 核心订单状态机分支覆盖率 96.30%；
- 全仓 Ruff 规则通过；
- Bandit 高严重度/高置信度结果为零；
- 故障注入集合 191 项通过；覆盖事务中 SIGKILL、kernel socket 黑洞、SQLite
  read-only 与真实 SQLITE_FULL；
- 一键非实盘验证把全部测试文件分成七个 suite，生成绑定 commit/tree/source
  manifest 的 write-once evidence，并永久声明 `production_admissible=false`；
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

仓库现在具备核心生产候选内核及持续 Demo 准入协议：Shadow/Active/Chaos 隔离、
durable probe saga、SLO/Gate v2、双签 `soak_epoch`、Object Lock exact-version
回读、外部 synthetic、每日不可变 ledger 和 Demo→Canary transition 的验证/
fail-closed 路径均已编码并有回归测试。Stage-C 的 13 个场景均已有确定性 parser
contract，但生产级 executor 仍全部未准入：其中 4 个外部状态场景只有仓内 Demo
test actor/unsigned raw collector（mutating CLI/unit 固定 fail-closed self-check），
3 个内部屏障只有隔离 test-executor，另外 6 个仍只有
parser/collector 积木；它们都不在 `implemented_stage_c_scenarios()`，不能生成生产
receipt。Canary 的 12 路通用 collector/signer、
systemd 隔离、实际凭据指纹、双对象恢复、独立 WORM/deployment verifier 和一次性
capability 已实现，但真实主机部署、IAM/STS receipt、Object Lock exact-version
回读仍是明确的外部前置条件；
此外尚未完成不能由代码伪造的外部事实和时间门槛，详见
`DEMO_OPERATIONS_RUNBOOK.md` 与 `RELEASE_CHECKLIST.md`。它们全部取得前结论始终是
**NOT ADMITTED**，不得描述为已达到无人值守生产准入。
