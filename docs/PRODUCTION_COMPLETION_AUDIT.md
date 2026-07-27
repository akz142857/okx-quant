# 生产方案逐条完成审计

审计日期：2026-07-27

审计对象：`PRODUCTION_PLAN.md` 1–19 节

结论：**仓库内实施与自动门禁已完成；生产准入尚未完成（NOT ADMITTED）**

本审计把“代码存在”“自动证据通过”和“真实环境准入”分开。只有下面所有
`EXTERNAL/TIME OPEN` 项取得不可变证据并通过 `scripts/production_gate.py`，才能把
原始目标标记为完成。

状态含义：

- `VERIFIED`：当前工作树有直接实现和自动化证据；
- `EXTERNAL OPEN`：必须使用真实 OKX、外部告警、对象存储或部署主机验证；
- `TIME OPEN`：必须经历规定的连续观察期；
- `APPROVAL OPEN`：必须由独立人员签署，代码不能代签。

## 1. 方案要求与当前证据

| 方案范围 | 状态 | 当前直接证据 | 尚缺证据 |
|---|---|---|---|
| 1.1 八项核心不变量 | VERIFIED | durable intent、累计 fill、UNKNOWN、硬模式、保护状态机、联合对账、candle 唯一约束、Decimal；对应 domain/execution/reconciliation/protection tests | 真实交易所行为仍由下述 contract/demo 项覆盖 |
| 2.1 SLO 观测机制 | VERIFIED | Prometheus histogram、durable 保护激活/启动对账样本、不可手填的 UTC 日报告、WS 状态、30 秒对账上限、5 分钟备份上限、独立 watchdog；demo 日锚显式绑定报告 SHA-256 | 实际月度可用性、真实保护 p95/p99、Page 延迟、RPO/RTO 测量为 EXTERNAL OPEN |
| 2.2 全部风险预算配置化 | VERIFIED | 单笔损失、单品种/总敞口、持仓数、日损、回撤、意图频率、spread、交易所滑点、K 线波动率、24h 流动性、行情年龄、无保护期限、连续 API/WS/数据库错误均为强类型配置且有编译期硬边界 | canary 资金预算审批为 APPROVAL OPEN |
| 3 模块化单体、单写者、持久化 | VERIFIED | bounded execution queue、单进程锁、SQLite WAL/FULL/foreign keys/busy timeout；`JournalRepository` 与 Exchange Reader/Trader 端口隔离具体实现 | 多实例/PostgreSQL 触发条件当前不成立 |
| 4 订单、fill、clOrdId、保护状态机 | VERIFIED | 乐观版本、非法倒退拒绝、累计成交差值/`tradeId` 幂等、永久 clOrdId、按 ordId/clOrdId cancel/amend、保护 UNKNOWN/emergency；确定性测试和 20,000 次随机状态提议 | 无仓库缺口 |
| 5 数据模型与事务边界 | VERIFIED | decisions/intents/fills/positions/protections/snapshots/reconciliation/reservations/events/outbox；账务值为十进制文本；BUY 风险检查与 intent/预留/事件在同一 `BEGIN IMMEDIATE`；schema v9 的完整 reconciliation checkpoint 支持从 fills+adjustments 重建仓位投影，旧不完整历史拒绝猜测 | 旧 v8 对账记录若已存在，只能诊断、不能自动完整重建，必须由真实联合对账形成新 checkpoint |
| 6 买卖、exit lease、禁止盲重试 | VERIFIED | POST/429 歧义写不重放并进入 UNKNOWN；进程级全局 rate limiter；主动退出与保护触发竞态；退出 3 秒端到端独立 Page 定时器；冻结余额和 late fill/fee 修正 | SPOT 冻结余额与 SELL `slippagePct` 的真实支持矩阵为 EXTERNAL OPEN；当前 SELL 不发送未经 capture 证明的字段 |
| 7 独立 OCO 与 trailing | PARTIAL | 独立 OCO、部分成交 amend、只收紧、reqId、lost ACK resolver、lot/tick 量化、非 FILLED 退出同步锁存 emergency；离线 contract 拒绝 ACK-only/泛化 51000/残留订单；真实 demo 成功后可生成保持引用关系的脱敏 v1 fixture | `evidence/demo-contract.json` 与真实 `okx-demo-contract-fixture.v1.json` 尚缺，不能把离线 Fake 证据升级为 VERIFIED；EXTERNAL OPEN |
| 8 私有 WS、重连与 K 线幂等 | VERIFIED | orders/balance_and_position/orders-algo、连接状态、订阅 ACK、REST baseline、generation/event fence、candle watermark、缺口/时钟/行情年龄门禁 | 真实长连断网演练为 EXTERNAL OPEN |
| 9 启动恢复与联合对账 | VERIFIED | DB integrity、单实例锁、账户 UID、时钟、余额/普通单/fill/algo 联合解释、保守修复、MANUAL_REVIEW | 人工制造真实孤儿单/外部持仓演练为 EXTERNAL OPEN |
| 10 分层风控与 kill switch | VERIFIED | READY 双重门禁、K 线内部连续性/结构/波动率、精度/现金/风险预留、日损/回撤 hard halt、Ed25519 双人 resume/flatten、epoch CAS、一次性消费 | 真实双人演练与签字为 APPROVAL OPEN |
| 11 日志、指标与告警 | VERIFIED | 全上下文字段 JSON 脱敏日志、指标/histogram、transactional outbox、UNKNOWN/风控/对账/WS/滑点/策略超时 Warning/Page、同步 Page challenge、独立 heartbeat watchdog | 实际告警到维护者的端到端证据为 EXTERNAL OPEN |
| 12 API/主机/配置/备份安全 | VERIFIED | root-owned 公钥/目录；trader/watchdog/backup 秘密隔离；数据库卷字节/inode watchdog；加密后回读；签名 ready manifest 绑定快照时点、账户/schema、key ID；S3 version round-trip 工具、分层 prune、独立盘/空间门禁；cold restore 同文件系统单次原子切换并强制 `okxquant-trader:okxquant-data 0640`，供隔离只读身份监控/归档 | key 权限/IP 白名单、SSH/防火墙/NTP、真实 S3 与空主机恢复为 EXTERNAL OPEN |
| 13 测试层次和故障清单 | PARTIAL | 单元/随机状态机/repository/WS replay/fault/shadow tests；当前本机 449 项通过（1 个 TCP-bind 测试因沙箱权限未执行）、故障集合 184 项通过；另含事务中 SIGKILL、OS socket 黑洞、只读 URI、真实 SQLITE_FULL；artifact 绑定 commit/tree/source hash 且脏树拒绝有效证据 | 目标提交 Linux CI、OKX demo E2E 与真实主机/代理/磁盘故障演练未执行，故整体测试验收仍为 EXTERNAL OPEN |
| 14 发布、迁移与回滚 | VERIFIED | v1→v9 顺序、逐版本事务化、失败可重入的 forward-only migration；release 自带 REVISION；实际源码/解释器/依赖字节+全配置+唯一有序 launch manifest 组合身份；root durable receipt；受控 Python 直启 main 且 main 内部防直调；材料损坏降级为不可 resume/READY、强制保留保护/退出能力的 hard-safe safety-only | 真实 Linux systemd verify/部署/回滚、receipt 与 safety-only 演练为 EXTERNAL OPEN |
| 15 Phase 0–6 仓库任务 | VERIFIED | `IMPLEMENTATION_STATUS.md` 与全量自动门禁 | 各 Phase 的真实环境验收仍见对应 OPEN 项 |
| 15 Phase 7 研究与灰度工具 | PARTIAL | 组合共享现金、连续 OOS、动态成本、可复现压力 producer、参数面；准入门从 365+ 日 benchmark 重算覆盖率/7 日最大缺口/真实日历 90 日牛熊区间，并从预注册完整 grid 重算连通平台；v2 source artifact 可重放，独立 research policy 绑定 exact S3 version/grid/scenario，独立 runner attestation 绑定完整 stress evidence | 具体策略原始制品、两份真实独立签名、30 日真实 demo 和 canary 尚未发生，不能标 VERIFIED；TIME/EXTERNAL/APPROVAL OPEN |
| 16 工程准入 | PARTIAL | 本地测试/覆盖率/Ruff/Bandit/build/fault 通过 | 目标提交 CI 链接、真实迁移恢复、demo contract 尚未签署 |
| 16 交易安全准入 | PARTIAL | 响应丢失、部分成交、WS 恢复和 kill switch 自动证据通过 | 30 日无差异、保护 p99、key 权限/IP 白名单和演练签字尚缺 |
| 16 量化准入 | OPEN | gate 会 fail closed，示例 evidence 当前正确输出 NOT ADMITTED | 尚无获批策略的正 OOS、完整周期、平台区、滑点和压力损失证据 |
| 16 运维准入 | PARTIAL | runbook 与 audit-order 实现存在 | 外部 Page、空主机 RTO、人工演练签字尚缺 |
| 18 最新 OKX 契约复核 | PARTIAL | clOrdId/ordId、累计成交、lotSz/tickSz 与 algo 独立接口已形成严格 adapter 与离线回归；录制器可生成脱敏 fixture | 最新官方契约仍须在发布时复核；attached、手续费扣币、冻结余额、SELL 滑点字段须真实 demo contract，EXTERNAL OPEN |
| 19 首个实施切片 | VERIFIED | Phase 1 六项及后续依赖均已实现 | 无仓库缺口 |

## 2. 当前自动证据

截至本次审计：

- `pytest -q -k 'not healthz_reports_liveness_while_readyz_reports_readiness'`：
  449 passed、1 deselected；被跳过用例需要本机沙箱禁止的 TCP bind，保留给 Linux CI；
- 核心订单状态机 branch coverage：96.30%，门槛 95%；
- 故障注入集合：184 passed、1 个相同 TCP-bind 用例在本机沙箱 deselected；
- Ruff、Bandit high/high、compileall、ShellCheck、`git diff --check`：通过；
- wheel/sdist：可以构建；
- `scripts/production_gate.py` 强制逐日独立监控签名、S3 SHA/version、durable SLO
  日报告 SHA、30 日 ledger head、动态成本/可重放原始数据 provenance、研究预注册/
  runner 两级签名与最终风险审批签名；
  缺任一公钥、签名或绑定值即失败，不能靠编辑 evidence JSON、布尔 `plateau`/
  `covers_full_cycle` 或重算本地 hash chain 误放行。
- `activate_release.py` 只在 evidence/approval 有效窗口内由 root 创建不可写 deployment
  receipt；后续重启复核实际源码、完整脱敏配置、launch manifest、evidence 和批准
  artifact 的所有哈希，而不因短效审批过期阻断已有仓位的安全内核。

这些只证明仓库级工程能力，不能签署下一节。

## 3. 尚未满足且无法在当前工作区伪造的条件

当前工作区没有非示例生产配置，相关凭据/基础设施环境变量均未提供。不得创建假证据
或把 FakeExchange 结果登记为真实演练。

必须依次取得：

1. 独立 OKX demo key、账户 UID 和隔离数据库；
2. `scripts/demo_contract.py` 的真实证据和脱敏 v1 fixture；
3. 私有 WS 断网、孤儿订单、冻结余额、kill switch 和 flatten 演练；
4. 外部 Page 到实际维护者的 ACK；
5. S3 异地加密归档和空主机 `<30 分钟` 恢复证据；
6. API key Read + Trade、Withdraw 关闭以及出口 IP 白名单证明；
7. 同一 commit/config/account 连续 30 个自然日、每天至少 20 小时的 demo ledger；
8. 同一 research manifest 下的正 OOS、365+ 日重算牛熊周期、完整参数网格、压力
   producer 输出、原始数据 provenance 和真实滑点；
9. 独立 operator/risk approver 与 canary 资金上限签署。

任何 commit、配置 hash 或账户 UID 变化都会清零第 7 项。全部证据填入
`ADMISSION_EVIDENCE.example.json` 的正式副本后，先用
`scripts/production_gate.py request` 生成绑定 evidence SHA 与 ledger head 的请求，
由独立风险审批人签名，再使用 `evaluate --approval ...`。只有退出码 0、
`"admitted": true` 且 `"signed_root_approval": true` 才能把完整目标标记完成。
