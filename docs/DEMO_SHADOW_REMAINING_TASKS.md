# Demo / Shadow 剩余任务与重新验证清单

更新日期：2026-07-29

关联方案：[`DEMO_SHADOW_VALIDATION_PLAN.md`](./DEMO_SHADOW_VALIDATION_PLAN.md)

外部执行交接：[`EXTERNAL_EVIDENCE_HANDOFF.md`](./EXTERNAL_EVIDENCE_HANDOFF.md)

Gate A 执行清单：[`GATE_A_EXECUTION_CHECKLIST.md`](./GATE_A_EXECUTION_CHECKLIST.md)

当前准入结论：**NOT_ADMITTED / EXTERNAL OPEN**

本文件以未完成任务为主体，并保留已关闭 P0 的简要审计记录。剩余任务属于以下
三类：

1. 尚未完成；
2. 已完成一部分，但还不能通过生产级验收；
3. 代码已实现，但因合并、新 schema、外部环境或证据不足必须重新检查。

不得用 fixture、手工 JSON、本机签名回执或代码评审替代真实
systemd/IAM/WORM/OKX Demo 运行证据。

## 0. 当前验证拓扑（单机多账户 profile）

本轮实际目标是“单台 Linux 主机上的小资金 Demo 验证”，不是多主机高可用部署：

- 使用一台 Linux 主机运行 systemd 服务；不要求三台机器或三个独立故障域；
- 建议使用三个 OKX Demo 子账户/API key：`demo-shadow`（Read-only）、
  `demo-active`（Read + Trade）、`demo-chaos`（Read + Trade）；也可在同一账户
  上按阶段停机后复用，但不能同时运行或混用 key；
- 单机内仍必须隔离 Unix UID/group、systemd unit、数据/备份目录、凭据、端口和
  network namespace；Chaos 演练必须停止 Active writer；
- 第二主机、跨账号 IAM/WORM、第二故障域和高可用切换属于生产扩展项，不是本轮
  单机验证的前置条件；
- Shadow 72h、Active 7d、Chaos matrix 和小资金审批仍保留，因为它们验证的是
  功能、恢复和运行稳定性，而非主机冗余。

### 单机验证的继续任务顺序

1. 在同一 Linux 主机创建/绑定 Shadow、Active 两个账户和两套 systemd 配置；按需再
   增加 Chaos 账户/配置；
2. 运行单机 preflight、真实 Demo contract 和清理/余额核对；
3. Shadow 连续 72 小时只读运行；
4. 停止 Shadow 后运行 Active 7 日小额 probe；
5. 停止 Active，在隔离 unit/netns/cgroup 上完成 6 项核心故障；18 项矩阵留给 Gate B；
6. 完成单机备份、恢复、监控和证据 exact-version 回读；
7. Gate A 通过后，由双人签署 Gate C 小资金 Canary；Gate B 才是生产准入。

以下 P1-05 的第二故障域/跨账号内容标为生产扩展，不阻塞上述单机验证；但在
宣称生产级高可用前仍必须完成。

### Gate A / Gate B 边界

`Gate A` 是本轮单机小资金 Demo 验证：要求 P0-03 的 Linux/systemd 证据、WP0
contract v2、至少 Shadow + Active 两个隔离账户（Chaos 账户可选但推荐）、真实
contract cleanup、Shadow 72h、Active 7d、最小重启/对账演练、单机 WORM
exact-version 回读和 daily ledger。

Gate A 的最小 Chaos 集合为 6 项：SIGTERM、SIGKILL、WS down/reconnect、REST
5xx/429/unknown、external fill、protection cancel。每项必须有独立 receipt，故障
作用域限制在对应 unit/netns/cgroup；禁止用 host reboot 或全机 iptables 破坏来替代。

`Gate B` 是未来生产准入：才要求 18/18 production executor/live bridge、三账户
完整 Chaos、第二故障域、30 日 clean day 和双人 Canary。Gate B 未完成时，Gate A
也只能说明“Demo 可验证”，不能宣称生产可用。

## 1. 当前权威状态（2026-07-29 最新复核）

- 上一冻结候选提交以 `git rev-parse HEAD` 为准；本轮审查修复仍需提交后重新确认
  工作树 clean，并在新 HEAD 上重算全部发布身份。
- 本轮修复后的本机全量验证：`806 passed, 3 skipped`；3 项属于 loopback socket
  与 macOS setgid 平台差异，Linux CI 已配置为禁止这些关键测试跳过。
- `ruff check .`、`compileall` 和 `git diff --check` 均通过。
- 18 个 Stage-C 场景当前在生产视角全部是 `EXTERNAL OPEN`；
  `implemented_stage_c_scenarios()` 和
  `production_instrumented_stage_c_scenarios()` 应继续为空集合。
- Shadow `0/72h`，Active Demo `0/7d`，正式 soak `0/30d`。

剩余任务共 **12 项**：仓内/部署工程 4 项（含 `TASK-P0-03`）、真实基础设施
3 项、不可压缩运行与审批 5 项。另有 7 项 P0 仓内工作已关闭并保留为审计记录。

| ID | 状态 | 下一交付物 | 前置依赖 |
|---|---|---|---|
| `P0-03` | `PARTIAL` | 冻结提交、干净 Linux CI、systemd 安全验证、重算 provenance | 干净候选 + 单台 Linux 主机 |
| `P1-01` | `PARTIAL / Gate B` | 18/18 独立 production executor inventory record | Linux/IAM/WORM 设计 |
| `P1-02` | `PARTIAL / Gate B` | 18/18 native raw → signed envelope → final loader live bridge | `P1-01` source roles |
| `P1-03` | `PARTIAL / Gate B` | 4 个 external actor 的 signer、Linux 实测、WORM/deployment attestation | `P1-02`, `P1-05` |
| `P1-04` | `EXTERNAL Gate A` | 单 Linux 主机 Shadow + Active 隔离回执（Chaos 账户可选） | OKX/Linux 运维权限 |
| `P1-05` | `EXTERNAL Gate A/B` | Gate A 最小 IAM/STS + 单机不可变 exact-version；Gate B COMPLIANCE/跨账号/第二故障域 | 云基础设施权限 |
| `P1-06` | `EXTERNAL Gate A` | 最终候选 WP0 contract evidence v2 | `P0-03`, `P1-04..05` |
| `P2-01` | `EXTERNAL Gate A 0/72h` | Shadow 连续 72 小时证据 | `P1-04..06` |
| `P2-02` | `EXTERNAL Gate A 0/7d` | Active Demo 7 日 burn-in | `P2-01` |
| `P2-03` | `EXTERNAL Gate A 0/6；Gate B 0/18` | Gate A 核心 Chaos；Gate B 最终 18 项 Chaos matrix | `P2-02`, release freeze |
| `P2-04` | `EXTERNAL Gate B 0/30d` | 30 个完整 UTC clean day | `P2-03`, epoch start |
| `P2-05` | `EXTERNAL Gate C` | Gate A 后双人签署、严格限额的小资金 Canary；Gate B 后才可生产准入 | `P2-01..03`, final Gate |

### 状态定义

| 状态 | 含义 |
|---|---|
| `TODO` | 尚未实现 |
| `PARTIAL` | 已有代码或测试资产，但协议/证据链未闭合 |
| `RECHECK` | 已实现，但当前工作树尚未重新全量验证 |
| `EXTERNAL` | 必须在真实外部环境产生证据 |
| `DONE` | 仓内实现与本地机器验证已完成；不代表外部生产准入 |

## 2. P0 基线恢复状态（2 项关闭，1 项剩余）

### TASK-P0-01：收口被中断的 recovery schema 升级

状态：`DONE`

已有：

- barrier challenge 已开始增加 `barrier_recovery_bindings`；
- native recovery bundle 已开始要求 `okx_stability_https` 和
  `journal_readiness_artifact`；
- observer key fingerprint、TLS certificate/SPKI、journal readiness hash 和
  stable double-read 的校验路径已部分实现。

完成：challenge、native bundle、assembler/projector 与 fixture 已统一为强制
recovery bindings；缺失 observer、错 TLS、错 readiness、双读变化与时序逆转均有
fail-closed 对抗测试。

验收：

- 上述 10 个失败全部消失；
- recovery 聚焦测试包含缺失 binding、错 key、错 TLS、错 readiness
  hash、不稳定双读和时序逆转的对抗用例；
- 继续 fail closed，不允许为了兼容旧 fixture 而将新字段改为可选。

### TASK-P0-02：完成同一 recovery evidence cut

状态：`DONE`

要求：

- journal readiness 回执绑定新 PID、systemd InvocationID、boot ID、
  reconciliation generation/run ID 和最后业务更新水位；
- runtime 进入不再发生 cleanup/cancel/新交易写的 evidence hold；
- OKX source 必须绑定 journal-readiness artifact hash，并对精确
  order/fill/algo/balance 执行稳定双读；
- 随后生成 final journal cut 和 final systemd cut；
- projector 强制 `ready <= OKX stable read <= final cut`、同 invocation/
  generation、区间无 mutation；
- 禁止把第二/第三次 runtime invocation 的事实拼成一次成功恢复。

验收：增加 invocation 串线、generation 漂移、中间撤单、第二次崩溃、
OKX 双读变化的对抗测试，全部必须拒绝。

### TASK-P0-03：冻结一个可复查候选

状态：`PARTIAL`（本地绿灯；干净 Linux 与冻结提交未完成，仍计入剩余任务）

验收命令：

```bash
.venv/bin/ruff check .
.venv/bin/python -m compileall -q okx_quant stage_c_test_harness scripts tests
.venv/bin/pytest -q
git diff --check
```

本地已完成全部四条验收命令。还必须：

- 在干净 Linux 环境独立跑全量 CI；
- 执行 systemd unit 语法/安全属性验证；
- 重算 parser manifest、implementation inventory 和 build provenance 摘要；
- 确认两个 production capability 查询仍为空集合。

## 3. 已关闭的 Stage-C P0 证明链（5 项审计记录）

### TASK-P0-04：保护单 parent ownership 进入独立 raw 证据

状态：`DONE`

已有：actor 在执行和 cleanup 前会通过 journal parent intent 校验
`parent clOrdId + exchange ordId + instId + algoClOrdId + algoId + qty`，不再猜测
或误撤无关 OCO。

完成：

- 新增 allowlisted SQLite query `stage-c-protection-ownership`；
- 返回唯一 parent intent/order/protection 联结行及 generation/snapshot 水位；
- external-fill 和 external-protection-cancel 采集计划增加
  `journal.protection_ownership`；
- 由独立 journal source 签名，OKX source 只签名自己的 raw bytes；
- core parser 交叉比较 parent clOrdId/ordId、双 algo ID、instId、qty 和状态；
- OKX algo fact 不得再合成或自报 parent `ord_id`。

验收：无关同品种/同数量 OCO、错 parent、错双 algo ID、重复 ownership
行或缺失 journal event 全部拒绝。

### TASK-P0-05：所有 OKX raw frame 绑定预注册 observer key

状态：`DONE`

已有：

- exact-release envelope 已拒绝同一 envelope 内混用不同 API key
  fingerprint；
- barrier recovery projector 已开始精确比较 expected fingerprint。

完成：非 barrier observer fingerprint 预注册，全部 OKX frame 精确绑定 challenge
中的 API key、TLS certificate 与 SPKI；混 key、错注册 key 和错 TLS 均被拒绝。

### TASK-P0-06：18 项统一不可变 implementation inventory

状态：`DONE`

当前分组：

| 组别 | 场景 | 当前资产 | 生产状态 |
|---|---|---|---|
| Legacy 5 | `ws-public`, `ws-private`, `ws-business`, `restart-sigterm`, `restart-sigkill` | repository producer | `EXTERNAL OPEN` |
| Black-box 10 | `backup-db-corruption`, `clordid-conflict`, `external-fill`, `external-pending-buy`, `external-protection-cancel`, `frozen-balance`, `oco-active-process-death`, `rest-5xx-429-unknown`, `restart-while-ws-down`, `ws-partial-fill-recovery` | parser；其中 4 项有 Demo actor | `PARSER_READY / EXTERNAL OPEN` |
| Barrier 3 | `barrier-buy-intent-before-post`, `barrier-fill-before-projection`, `barrier-post-before-ack` | 隔离 test-only harness | `PARSER_READY / EXTERNAL OPEN` |

已确认：

- Legacy 5 不再使用 `IMPLEMENTED` 表示生产能力，统一为
  `REPOSITORY_PRODUCER / EXTERNAL OPEN`；
- 18 项全部进入同一 append-only inventory、parser contract、semantic
  verifier、challenge/workload/source 和 deployment attestation 模型；
- 不得把 actor、parser、test hook、文件存在或签名 JSON 自动升级为
  `EXECUTOR_SHIPPED`。

验收：当前 18/18 明确 OPEN；未来每个场景必须分别通过
`PARSER_READY -> EXECUTOR_SHIPPED -> DEPLOYMENT_ATTESTED`，不允许批量布尔开关升级。

### TASK-P0-07：inventory v2 合并后重新安全复核

状态：`DONE`

已实现并在当前合并工作树全量验证：

- inventory/artifact schema v2；
- fixed semantic verifier dispatch、verifier source hash 和 strict result schema；
- security test 源码 bytes/hash、真实 test function、canonical result bytes/hash 和
  passed outcome；
- exact-release/test-only build provenance 与 hook 限制；
- parser bundle、dependency lock、interpreter 运行时身份；
- registrar/capability trust roots 及 policy；
- WORM 五职责、driver 和全部 artifact 按 SHA 禁止复用。

验收：重跑 inventory/protocol/build/full suite，确认运行时 registry 重绑、伪造
test result、错 build class、缺 lock/interpreter、重用 key/blob 全部拒绝，且 13 个
record 仍全部 OPEN。

### TASK-P0-08：Stage-C 候选部署身份和时序进入 Gate

状态：`DONE`

已关闭的问题：receipt 不能仅绑定 release、soak epoch ID 和粗粒度开始时间，
必须证明 18 项使用预批准的 Chaos account/config/unit/host image/netns/key/
safety behavior，并强制完整 matrix 在正式 epoch 开始前完成。

完成：

- 在 candidate manifest/epoch 中预注册 `stage_c_chaos_deployment_identity`；
- 包含 account UID、config hash、unit、host image、boot/netns/cgroup policy、
  API/source key fingerprints、instrumented build identity 和 normalized safety behavior
  hash；
- 18 张 receipt 精确匹配该身份；
- Gate 强制
  `release_frozen_at <= drill.started_at <= drill.completed_at <= epoch.started_at`；
- release/config/safety behavior 任一变化都使旧 matrix 失效。

## 4. 剩余仓内/部署工程（4 项，含 TASK-P0-03）

### TASK-P1-01：逐场景交付 18 个 production executor

状态：`PARTIAL`（18 个场景现均有显式 inventory record；仍为 `EXECUTOR_SHIPPED=0/18`）

仓内已补齐 `full_stage_c_inventory_document()`：它把 13 个 native parser
记录与 5 个 legacy repository-producer 记录合并为可审计的 18 项视图。legacy
记录明确标记为 `REPOSITORY_PRODUCER / EXTERNAL OPEN`，不会参与
`implemented_stage_c_scenarios()`、`production_instrumented_stage_c_scenarios()`
或 parser inventory digest，因此不能被文件存在、fixture 或本地签名升级为
`EXECUTOR_SHIPPED`。仍缺 Linux/IAM/WORM/部署实证以及每场景独立 fault contract。

当前 `EXECUTOR_SHIPPED = 0/18`。每个场景必须独立交付：

- exact driver artifact 和 build provenance；
- 受控故障原语，且只能在 Demo/Chaos 故障域执行；
- raw collector、source signer、systemd unit/cgroup/UID 和 IAM policy；
- durable pre-intent checkpoint 和全局一次性 challenge consumption；
- 场景特定 semantic verifier 及对抗测试；
- cleanup/reconciliation/postcondition 和失败时的安全收敛；
- WORM publisher、independent exact-version readback 和 fleet/deployment
  attestation。

不允许用“一个通用 executor”在没有场景语义校验的情况下一次升级
多个场景。

### TASK-P1-02：production native artifact 到最终 parser 的 live bridge

状态：`PARTIAL`（18 个场景均已注册独立 native contract；13 个 native Stage-C
场景已有 fail-closed bridge/parser，5 个 legacy producer 已接入同一 contract
resolver 与 raw-collection schema，但尚无真实 executor/部署证据，故 18/18
live bridge 仍未完成）

仓内 bridge 已能将独立 acquirer 的原始 request/response bytes 通过 source
signer 组装为 canonical JSONL，并由最终 parser 重新验证 challenge、一次性
consumption、workload/source key、native bytes 和场景 facts。parser 现在还拒绝
重复 JSON key 与非 canonical JSONL，避免 envelope 的 last-key-wins 歧义。
这些代码路径和 fixture 只能证明协议拒绝/重算行为，不能替代 18 项真实
Linux/IAM/WORM/部署证据；5 个 legacy 场景现在已经注册独立 driver contract、
source-role map、场景语义校验和同一 raw collection/signed-fragment bridge，
但仍需真实 collector/signature units 与部署证据。

需要：

- 将 collector 的真实 raw bytes 输出为固定 JSONL/event envelope；
- 绑定 challenge、workload、source key、exact request、snapshot/generation 和
  predecessor hash；
- parser 只允许从 raw bytes 重算 facts，禁止 summary 自报；
- final loader 在读 receipt 之前验证 registrar、capability、consumption、
  deployment、WORM 和所有 source signatures；
- 对 18 项全部实现，包括 5 个 legacy producer 和 3 个 barrier；当前 legacy
  仅达到 repository contract/bridge-ready，不能改变 `EXECUTOR_SHIPPED=0/18`。

### TASK-P1-03：将 4 个 external actor 从自检升级为可部署 producer

状态：`PARTIAL`

已完成：`prepare/cleanup` 不再是 self-check；在变异前验证 registrar 签名
challenge、全局 consumption receipt 和 live PID/UID/cgroup/invocation/interpreter，
写入幂等 durable pre-intent checkpoint，并以真实 OKX Demo client 执行受限动作；
独立 OKX/journal collector 与 cleanup unit 已接入同一流程。

仍未完成：

- 在真实 Linux 上证明 concurrent oneshot orchestration、PID attestation、超时与
  cleanup timer 不死锁；
- 为两个 raw collector 部署独立 source signer unit、凭据与最小权限；
- 将其输出接入 TASK-P1-02 final live bridge、WORM/readback 与 deployment attestation；
- 提供真实 DynamoDB conditional consume、systemd/netns/cgroup 和 OKX Demo 证据；
- 只允许真实 OKX Demo，单次名义金额继续受 5–10 USDT 硬上限。

## 5. 剩余真实部署与证据基础设施（3 项）

### TASK-P1-04：单台 Linux 主机上的多账户隔离

状态：`EXTERNAL`

- `demo-shadow`：干净零持仓子账户，Read-only key（Gate A 必需）；
- `demo-active`：干净子账户，只允许 validation probe 的 Trade key（Gate A 必需）；
- `demo-chaos`：独立子账户，在同一主机使用独立 netns/cgroup/credential/egress（Gate A
  可选，Gate B 必需）；
- 旧账户约 1 BTC 基线资产不得作为正式 Shadow/Chaos 账户。

本轮不要求三台主机；必须证明同机 UID、目录、凭据、端口和 namespace 不串线，
并在 Chaos 演练前停止 Active writer。第二主机和跨主机切换属于生产扩展。

若资源不足而分阶段复用账户，必须更换独立 key/profile，并确认 flat、无挂单/算法单，
导出 pre/post balance/order baseline；复用账户的证据不计作独立角色或故障域证明。

### TASK-P1-05：单机最小 IAM/STS、不可变存储与生产扩展

状态：`EXTERNAL`

- Gate A：最小 IAM/STS、单机不可变 evidence store、exact-version 回读和签名校验；
  至少拆分 publisher 与 verifier 的进程/签名 key，不得同一 root/key 自写自验；
- Gate B：Object Lock COMPLIANCE、retention、deny-delete 和 KMS policy；
- Gate B：bundle publisher、raw observer、deployment verifier、fleet admission gate、
  WORM readback verifier 五职责和 IAM principal 分离；
- 跨账号 exact-version GET，重算 bytes/hash/signature；
- 真实 IAM principal/STS session receipt；
- 单机验证至少完成 Gate A 的 IAM/STS 最小权限和 exact-version 回读；Object Lock
  COMPLIANCE、跨账号职责分离和第二故障域 monitor/Page/ACK/restore verifier 标记为
  Gate B 生产扩展；
- 不得把同机 root、不同文件路径或复制的同一私钥视为独立身份。

### TASK-P1-06：正式候选上重新生成 WP0 contract evidence v2

状态：`EXTERNAL`

需要绑定干净 git commit/tree/source manifest、config hash、account UID、key
fingerprint、exact OKX Demo 契约结果。Gate A 使用单机不可变 receipt + detached
signature/exact readback；Gate B 再绑定 WORM object/version/retention 和跨域独立回读签名。

## 6. 不可压缩的持续运行阶段（5 项）

### TASK-P2-01：Shadow 预热

状态：`EXTERNAL`，进度 `0/72h`

退出门槛：72 小时零交易所写、持续 Read-only 权限、0 unexplained
mismatch、WS 重连/恢复/SLO/资源门槛全部通过。

### TASK-P2-02：Active Demo burn-in

状态：`EXTERNAL`，进度 `0/7d`

退出门槛：至少 7 个完整 probe saga、7 个保护生命周期、14 个 execution，
UNKNOWN 三分支、backup/Page/SLO 连续通过。

### TASK-P2-03：最终候选 Chaos matrix

状态：`EXTERNAL`，进度 `0/18`

必须在修复 burn-in 缺陷并重新冻结 release/config 后执行。18 项必须全部
绑定 TASK-P0-08 的同一 candidate deployment identity，且在正式 soak epoch
开始前完成。

### TASK-P2-04：Gate B 正式 30 个完整 UTC clean day

状态：`EXTERNAL`，进度 `0/30d`

每天必须有 journal/monitor/alert/backup 四类 exact-version 原始证据和独立签名；
任一硬门槛失败、证据日缺失或 release/config 变化都使 streak 重新计数。

### TASK-P2-05：Gate C 小资金 Canary 审批

状态：`EXTERNAL`

Gate A 通过后，可由独立 operator/risk 签署最长 6 小时、严格限额/日亏/自动 HALT
和回滚条件的小资金 transition policy；这不自动授权 full production。Gate B 完成
后才可申请生产级准入。

## 7. 执行顺序

1. Gate B 的 `TASK-P1-01/P1-02/P1-03` 继续作为生产扩展，逐场景交付并验证 18/18
   production executor/live bridge；不得批量升级能力状态。
2. 完成 `TASK-P0-03`：冻结提交，在干净 Linux CI 重跑并生成新的 manifest、
   inventory 与 build provenance。
3. 完成 Gate A 的 `P1-04/P1-05/P1-06`：单机账户隔离、最小 IAM/exact-version
   回读和 WP0 v2 evidence。
4. 在同一冻结候选上依次执行 `72h -> 7d -> 6-item core chaos`，通过后进入 Gate C
   小资金审批。
5. 若目标是生产准入，再继续 Gate B 的 `18-item matrix -> 30d -> 第二故障域`。

## 8. Gate A / Gate B 完成定义

Gate A（单机 Demo 验证）完成条件：

- 当前冻结提交在 macOS 和目标单台 Linux CI 上全量绿灯；
- Shadow/Active 账户、systemd UID/目录/凭据/netns 隔离和 live preflight 有真实回执；
- Demo contract v2、Shadow 72h、Active 7d、6 项核心 Chaos 和单机 exact-version
  evidence 全部绑定同一候选；
- 最终 Gate C 双签小资金策略包含限额、日亏、自动 HALT、人工回滚和最长 6 小时；

Gate B（生产扩展）完成条件：

- 18/18 场景均有不可变 inventory、场景语义 verifier、真实 executor、
  native live bridge 和 deployment attestation；
- Demo contract v2、Shadow 72h、Active 7d、final Chaos matrix、30 clean days
  全部绑定同一最终候选和预批准部署身份；
- IAM/STS、WORM COMPLIANCE、跨账号 exact-version readback、第二故障域和
  职责分离均有机器可验证证据；
- 最终 Gate 无人工 override，且任一缺失/过期/不匹配证据都 fail closed；
- 独立子 Agent 完成最终对抗复审，所有 P0/P1 均已修复或有被 Gate
  强制的明确外部阻断证据。
