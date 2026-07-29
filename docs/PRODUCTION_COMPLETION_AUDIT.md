# 生产方案逐条完成审计

审计日期：2026-07-28

审计对象：`PRODUCTION_PLAN.md` 1–19 节

结论：**核心生产候选内核和持续 Demo/Gate v2 仓库能力已实现；真实基础设施、时间
门槛与独立审批证据尚未取得，生产准入未完成（NOT ADMITTED）**

本审计把“代码存在”“自动证据通过”和“真实环境准入”分开。只有下面所有
`IMPLEMENTATION/EXTERNAL/TIME/APPROVAL OPEN` 项完成，并通过升级后的
`scripts/production_gate.py`，才能把原始目标标记为完成。

状态含义：

- `VERIFIED`：当前工作树有直接实现和自动化证据；
- `PARTIAL`：已有基础实现，但仍有实现或证据缺口；
- `IMPLEMENTATION OPEN`：多角色评审确认仍需修改仓库代码或部署制品；
- `EXTERNAL OPEN`：必须使用真实 OKX、外部告警、对象存储或部署主机验证；
- `TIME OPEN`：必须经历规定的连续观察期；
- `APPROVAL OPEN`：必须由独立人员签署，代码不能代签。

## 1. 方案要求与当前证据

| 方案范围 | 状态 | 当前直接证据 | 尚缺证据 |
|---|---|---|---|
| 1.1 八项核心不变量 | VERIFIED | durable intent、累计 fill、UNKNOWN、硬模式、保护状态机、联合对账、candle 唯一约束、Decimal；对应 domain/execution/reconciliation/protection tests | 真实交易所行为仍由下述 contract/demo 项覆盖 |
| 2.1 SLO 观测机制 | PARTIAL | SLO/Gate v2 从 durable WS、证据覆盖、保护、滑点、probe、alert ACK、backup、clock、resource 和 reconciliation facts 重算；完整 UTC 日、双签 epoch、不可变 invalid ledger 已实现 | 尚未在隔离 Linux/OKX Demo/S3/告警基础设施上形成真实 72h、7d、30d 序列 |
| 2.2 全部风险预算配置化 | VERIFIED | 单笔损失、单品种/总敞口、持仓数、日损、回撤、意图频率、spread、交易所滑点、K 线波动率、24h 流动性、行情年龄、无保护期限、连续 API/WS/数据库错误均为强类型配置且有编译期硬边界 | canary 资金预算审批为 APPROVAL OPEN |
| 3 模块化单体、单写者、持久化 | PARTIAL | bounded execution queue、本地单进程锁、SQLite WAL/FULL；backup/alert 外部进程只发布签名回执；Active/Chaos 使用独立 account coordination lease，所有 REST 写在 socket write 前重验 | broker token 不被 OKX 执行，跨主机自动接管仍须唯一写代理或 STONITH/key/egress 隔离与 recovery reconciliation；EXTERNAL OPEN |
| 4 订单、fill、clOrdId、保护状态机 | VERIFIED | 乐观版本、非法倒退拒绝、累计成交差值/`tradeId` 幂等、永久 clOrdId、按 ordId/clOrdId cancel/amend、保护 UNKNOWN/emergency；确定性测试和 20,000 次随机状态提议 | 无仓库缺口 |
| 5 数据模型与事务边界 | VERIFIED | schema v11；decisions/intents/fills/positions/protections/snapshots/reconciliation/reservations/events/outbox/probe/alert lifecycle；账务值为十进制文本；BUY 风险检查与 intent/预留/事件在同一 `BEGIN IMMEDIATE`；完整 checkpoint 支持从 fills+adjustments 重建仓位投影，旧不完整历史拒绝猜测 | 旧 v8 对账记录若已存在，只能诊断、不能自动完整重建，必须由真实联合对账形成新 checkpoint |
| 6 买卖、exit lease、禁止盲重试 | VERIFIED | POST/429 歧义写不重放并进入 UNKNOWN；全局 rate-limit 等待后、socket write 前重验 writer/entry/probe capability；主动退出与保护触发竞态；退出 3 秒独立 Page；未保护仓位 watchdog 只读 WS cache、异步退出 | SPOT 冻结余额与 SELL `slippagePct` 的真实支持矩阵为 EXTERNAL OPEN；当前 SELL 不发送未经 capture 证明的字段 |
| 7 独立 OCO 与 trailing | PARTIAL | 独立 OCO、部分成交 amend、只收紧、reqId、lost ACK resolver、lot/tick 量化、非 FILLED 退出同步锁存 emergency；离线 contract 拒绝 ACK-only/泛化 51000/残留订单；2026-07-28 交互式 OKX Demo 已验证市价买卖、独立 OCO ACTIVE、attached TP/SL ACTIVE、撤单与清理，脱敏 v1 fixture 可通过校验器 | 当前 v1 证据未绑定完整 release/config/account 与 Object Lock exact version，且尚未证明持续 runtime 的保护 p95/max；在 v2 发布级证据完成前保持 PARTIAL；EXTERNAL OPEN |
| 8 私有 WS、重连与 K 线幂等 | VERIFIED | orders/balance_and_position/orders-algo、连接状态、订阅 ACK、REST baseline、generation/event fence、candle watermark、缺口/时钟/行情年龄门禁 | 真实长连断网演练为 EXTERNAL OPEN |
| 9 启动恢复与联合对账 | VERIFIED | DB integrity、单实例锁、账户 UID、时钟、余额/普通单/fill/algo 联合解释、保守修复、MANUAL_REVIEW | 人工制造真实孤儿单/外部持仓演练为 EXTERNAL OPEN |
| 10 分层风控与 kill switch | VERIFIED | READY 双重门禁、K 线内部连续性/结构/波动率、精度/现金/风险预留、日损/回撤 hard halt、Ed25519 双人 resume/flatten、epoch CAS、一次性消费 | 真实双人演练与签字为 APPROVAL OPEN |
| 11 日志、指标与告警 | PARTIAL | 脱敏日志、Prometheus/Grafana、transactional outbox、稳定 event ID、持久 attempt/provider received/human ack/escalation/DLQ、Page challenge、独立 watchdog 和外部 synthetic；监控签名事实取自 endpoint 实际 account/unit/epoch，缺失或错配 fail closed | 真实第二故障域 dead-man、provider/human receipt 和值班升级时延仍为 EXTERNAL OPEN |
| 12 API/主机/配置/备份安全 | PARTIAL | root-owned 密钥边界；Shadow/Active/Chaos user/group/netns/release/state 隔离；本地归档每分钟、Demo/生产每两分钟 exact restore；KMS + Object Lock COMPLIANCE、signed receipt、exact archive/manifest GET、fsync 后原子发布和 cold restore 已实现；独立日 verifier 从原始 SQLite 重建 facts 并核对四类 external artifacts | 真实 S3 bucket policy/跨账号验证、completed RPO≤5m 与空主机端到端 RTO<30m 为 EXTERNAL OPEN |
| 13 测试层次和故障清单 | PARTIAL | 单元/随机状态机/repository/WS replay/fault/shadow/probe/SLO/canary tests；一键非实盘报告覆盖全部测试文件并强制标记不能生产准入；另含事务中 SIGKILL、OS socket 黑洞、只读 URI、真实 SQLITE_FULL；Stage-C 固定 18 项 inventory，其中 5 项自动 producer 已实现、13 项缺失能力在读取 receipt 前 fail closed；通用 allowlist collector/fault primitive 和 DynamoDB 条件消费 receipt 已就绪；artifact 绑定 commit/tree/source hash 且脏树拒绝成为发布证据 | 10 个场景专用 raw driver/parser、3 个 instrumented barrier producer、目标提交 Linux CI、持续 OKX Demo/Shadow 与真实主机/代理/磁盘故障演练尚未完成，故整体测试验收仍为 IMPLEMENTATION/EXTERNAL OPEN |
| 14 发布、迁移与回滚 | VERIFIED | v1→v11 顺序、逐版本事务化、失败可重入的 forward-only migration；release 自带 REVISION；实际源码/解释器/依赖字节+全配置+唯一有序 launch manifest 组合身份；root durable receipt；受控 Python 直启 main 且 main 内部防直调；材料损坏降级为不可 resume/READY、强制保留保护/退出能力的 hard-safe safety-only | 真实 Linux systemd verify/部署/回滚、receipt 与 safety-only 演练为 EXTERNAL OPEN |
| 15 Phase 0–6 仓库任务 | VERIFIED | `IMPLEMENTATION_STATUS.md` 与全量自动门禁 | 各 Phase 的真实环境验收仍见对应 OPEN 项 |
| 15 Phase 7 研究与灰度工具 | PARTIAL | 组合共享现金、连续 OOS、动态成本、可复现压力、预注册研究；正式 schedule 在 epoch 前锁定并均衡 4×2×2 联合格；日报/30 日 Gate 强制 residual IDs 精确等于 DONE probes；Canary 严格 schema、12 路 collector/signer/systemd、冻结 request/executable/WORM locator、四权独立验证与不可绕过的 external-readiness Gate 已实现，CLI 不接受本地 source artifact | 12 路 Canary 真实主机部署、IAM/STS/Object Lock/deployment attestation，以及具体策略原始制品、真实独立签名、30 日真实 Demo 和 Canary 尚未发生；TIME/EXTERNAL/APPROVAL OPEN |
| 16 工程准入 | PARTIAL | 本地测试/覆盖率/Ruff/Bandit/build/fault 和非实盘 evidence 通过；交互式 Demo contract 行为验证通过 | 修复后的目标提交 CI 链接、真实迁移恢复，以及绑定 release/config/account 的 Demo contract v2 证据尚未签署 |
| 16 交易安全准入 | PARTIAL | 响应丢失、部分成交、WS 恢复、kill switch、durable probe saga、Shadow Read-only/Chaos 隔离检查和完整 UTC v2 Gate 自动证据通过 | 30 个真实 clean day、保护 p95/max、key/IP 和演练签字尚缺 |
| 16 量化准入 | OPEN | gate 会 fail closed，示例 evidence 当前正确输出 NOT ADMITTED | 尚无获批策略的正 OOS、完整周期、平台区、滑点和压力损失证据 |
| 16 运维准入 | PARTIAL | runbook 与 audit-order 实现存在 | 外部 Page、空主机 RTO、人工演练签字尚缺 |
| 18 最新 OKX 契约复核 | PARTIAL | clOrdId/ordId、累计成交、lotSz/tickSz 与 algo 独立接口已形成严格 adapter 与离线回归；真实 Demo 已验证 attached TP/SL、基础币手续费、独立 OCO 和清理残尘，录制器已生成可校验的脱敏 fixture | 最新官方契约仍须在发布时复核；冻结余额、SELL 滑点字段、持续 API 行为及 release-bound 采集仍须真实 Demo 取证，EXTERNAL OPEN |
| 19 首个实施切片 | VERIFIED | Phase 1 六项及后续依赖均已实现 | 无仓库缺口 |

## 2. 当前自动证据

截至本次审计：

- 完整、不可漏项 pytest inventory 已纳入本地门禁；目标提交仍须由 Linux CI 出具报告；
- 本轮修复后的本机全量回归为 806 passed、3 项平台差异跳过；Linux CI 已禁止这些
  关键测试跳过，Ruff 全绿；
- 核心订单状态机 branch coverage：95.58%，门槛 95%；全项目 branch coverage：
  68%，CI 防回退门槛 65%；
- 故障注入语义集合：191 passed；
- `scripts/non_live_validation.py` 七个 suite 全部通过，并正确输出
  `production_admissible=false`；当前开发报告因工作树有本轮改动而不会成为发布证据；
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

1. 为 shadow/active/chaos 分配独立 OKX demo key、账户 UID、Unix 身份、release、
   数据库和状态目录；Shadow 使用 Read-only，Chaos 位于独立故障域；
2. 把已通过的交互式 `scripts/demo_contract.py` 行为验证升级为绑定
   release/config/account、detached manifest 和 Object Lock exact version 的 v2
   发布证据；
3. 私有 WS 断网、孤儿订单、冻结余额、kill switch 和 flatten 演练；
4. 在 Active/Chaos 实际执行 durable probe saga、UNKNOWN 三分支与逐 barrier 重启恢复；
5. 用已实现的 SLO/Gate v2、`soak_epoch`、完整 UTC 日结和不可变 invalid 行开始正式计时；
6. 外部 Page 的 ingestion/provider/human ACK 分层及第二故障域 dead-man；
7. S3 Object Lock 异地加密归档、completed RPO≤5分钟和空主机 `<30 分钟` 恢复；
8. API key 最小权限、Withdraw 关闭以及出口 IP 白名单证明；
9. 同一 soak epoch 连续 30 个完整 UTC clean day 的 v2 demo ledger；
10. 同一 research manifest 下的正 OOS、365+ 日重算牛熊周期、完整参数网格、压力
   producer 输出、原始数据 provenance 和真实滑点；
11. Demo release identity → Canary deployment identity transition，以及机器可执行的
    短效 canary policy 和独立 operator/risk approver 签署。
12. 实现并部署 Stage-C 尚缺的 10 个独立 raw driver/parser 与 3 个 instrumented
    barrier producer；当前 Gate 会在读取 receipt 前拒绝；
13. 在真实隔离主机部署仓内已有的 12 路 Canary collector/signer 与独立
    WORM/deployment/capability units，取得 IAM/STS、实际凭据指纹、Object Lock
    exact-version 和部署 attestation；当前 production readiness 因缺外部事实固定拒绝。

任何冻结 release/deployment identity 变化都会关闭当前 epoch；任何 hard breach
都会追加 invalid 行并打断 streak。全部证据填入
`ADMISSION_EVIDENCE.example.json` 的正式副本后，先用
`scripts/production_gate.py request` 生成绑定 evidence SHA 与 ledger head 的请求，
由独立风险审批人签名，再使用 `evaluate --approval ...`。只有退出码 0、
`"admitted": true` 且 `"signed_root_approval": true` 才能把完整目标标记完成。
