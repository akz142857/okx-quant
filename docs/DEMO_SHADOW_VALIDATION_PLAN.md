# Demo / Shadow 持续运行与长期稳定性验证计划

更新时间：2026-07-29

状态：**多角色评审后的仓库实现已完成本轮安全收敛；真实部署、72 小时/7 日/30 日准入时钟均未开始**

> 当前用户验证采用 `DEMO_SHADOW_REMAINING_TASKS.md` 定义的 Gate A：单台 Linux
> 主机、Shadow + Active 多账户（Chaos 可选）、同机 UID/unit/目录/netns/cgroup
> 隔离。本文后续涉及三主机、第二故障域、18 项完整生产 executor、跨账号 WORM
> 和 30 日 production soak 的内容属于 Gate B 生产扩展，不是 Gate A 小资金验证的
> 前置条件。Gate A 通过后仍需 Gate C 双人签署、严格限额和自动 HALT 才能做小资金
> Canary；不能将 Gate A 直接称为生产准入。
>
> 阅读规则：本文未显式标注 Gate A 的“生产/正式/最终 Gate”条款，均属于 Gate B
> 生产扩展；不得把 Gate B 的三账户、第二故障域、18 项或 30 日条件倒灌为当前
> 单机 Demo 的前置条件。

未完成、部分完成与需重新检查的任务统一记录在
[`DEMO_SHADOW_REMAINING_TASKS.md`](./DEMO_SHADOW_REMAINING_TASKS.md)。该清单的当前测试状态
优先于本方案中的历史绿灯数字。

## 1. 目标与结论

本阶段不使用真实资金，目标是把以下能力从“代码与离线测试已实现”升级为“在真实
OKX Demo、真实公网和生产同构主机上持续成立”：

1. public / private / business WebSocket 长连接、断线检测、重连和 REST baseline；
2. 订单、fills、余额、普通挂单和 algo 保护单的联合对账；
3. SIGTERM、SIGKILL、网络故障和主机重启后的安全恢复；
4. metrics、heartbeat、外部 watchdog、Page、备份和每日 SLO 证据；
5. 同一 soak epoch、release/deployment identity 连续 30 个完整 UTC 日的长期稳定性。

本阶段完成后，只能申请进入极小资金 Canary 审批，不能自动获得实盘准入。策略盈利、
真实资金权限、真实盘口冲击和人员责任仍需单独验证。

预计投入：

- 工程补齐与演练：15–25 人日；
- Shadow 预热：连续 72 小时；
- Active Demo burn-in：连续 7 天；
- 正式准入观察：连续 30 个自然日；
- 独立评审和 Canary transition：2–3 个工作日；
- 总日历时间：约 8–10 周，任何发布身份变化或硬门槛失败都会延长。

本计划中的“完成”有三个不同层次：

1. 工作包实现并通过自动测试；
2. 在 Demo/生产同构主机上取得真实证据；
3. 证据被不可变保存、独立复验并被最终 Gate 机器强制。

只有第三层完成才能开始或累计正式 30 日；不能用“代码已经实现”替代运行证据。

## 2. 当前基线与证据强度

### 2.1 已有能力

- 上一冻结候选提交以 `git rev-parse HEAD` 为准；本轮审查修复仍需提交后重新确认
  工作树 clean，并在新 HEAD 上重算发布身份；
- 2026-07-29 本轮修复后的本机全量回归为 `806 passed, 3 skipped`；3 项属于
  loopback socket 与 macOS setgid 平台差异，Linux CI 已配置为禁止这些关键测试
  跳过。`ruff check .`、`compileall` 和 `git diff --check` 通过；目标 Linux CI
  仍必须在冻结提交上独立全量通过，不能把本地回归替代发布 CI；
- OKX Demo 网络和私有 API 鉴权通过；
- BTC-USDT Demo 契约已真实验证：
  - 市价买入/卖出；
  - 独立 OCO ACTIVE；
  - attached TP/SL ACTIVE；
  - algo 撤销和退出成交；
  - 手续费后的子 `lotSz` 尘埃精确闭合；
- `ProductionRuntime` 已接入 public/private/business WS、双 REST baseline、事件 fence；
- `Reconciler` 已联合解释 orders、fills、balance、positions 和 algo protection；
- 已有 startup recovery、周期对账、heartbeat、Prometheus endpoint、告警 outbox、
  watchdog、在线备份、SLO 日报告和 30 日签名 ledger。

### 2.2 仍不能声称已验证

当前 Demo contract 证明了交易所行为，但其 evidence 尚未绑定完整 commit、config
hash、账户 UID 和不可变对象版本，因此还不是发布级准入证据。现有 WS、恢复、Page
和备份结论主要来自 FakeExchange、replay 或本机故障测试，尚无真实 Demo 长连和
systemd 主机证据。

当前 Demo 账户在契约测试前已有约 1 BTC 基础币余额。Shadow 禁止交易所写操作，
无法为该非 dust 资产创建保护；生产内核会按设计拒绝 READY。因此该账户只能用于
contract 或明确的已有仓位保护/恢复演练，不能直接作为正式零持仓 Shadow、Active
或通用 Chaos 账户。

## 3. 环境与账户隔离（Gate A / Gate B）

Gate A 只要求在一台 Linux 主机上建立 Shadow + Active 两个互不共享 key、账户、
Unix 身份、数据库、状态目录、release 路径和 metrics 端口的 Demo 环境。Chaos
环境可选但推荐；以下第三行和“第二故障域”条款仅在 Gate B 启用：

| 环境 | 用途 | API 权限 | Shadow | 是否计入 30 日 |
|---|---|---|---:|---:|
| `demo-shadow` | 信号、WS、REST 对账、资源趋势 | **Read-only** | true | 否 |
| `demo-active` | 受限 probe、保护、滑点、正式 soak | Read + Trade | false | 是 |
| `demo-chaos` | 外部订单、断网、SIGKILL、恢复演练 | Read + Trade | false | 否 |

Gate A 硬要求：

- 每个环境使用独立 OKX Demo 子账户和 Key，全部禁止 Withdraw；
- `demo-shadow` 必须使用不具备 Trade 权限的 Read-only Key；除了应用层
  `shadow_mode`，还要由凭据权限和受审计的写端点 deny/proxy 形成能力隔离；
- `demo-active` 和 `demo-chaos` 的 Trade Key 不能被 Shadow 进程、用户或环境文件读取；
- `demo-shadow` 必须只有 USDT，或所有非 USDT 余额同时低于 dust 和 `lotSz`；
- `demo-active` 在开始正式 30 日观察前必须清空旧订单、旧 algo 和不可解释持仓；
- `demo-chaos` 若启用，使用独立子账户和同机 network namespace、
  Unix UID/group、cgroup、release symlink 和精确出站故障代理，不能用主机级
  `iptables`、网络重启或共享 release 切换影响 Active；
- 启用的环境分别使用：
  - `/var/lib/okx-quant/demo-shadow/`
  - `/var/lib/okx-quant/demo-active/`
  - `/var/lib/okx-quant/demo-chaos/`
- 每套启用的服务使用不同 trader/watchdog/backup Unix 身份和不同环境文件；环境文件必须为
  `root:<environment-trader> 0640`，目录链不可组写、不可使用不受控符号链接；
- systemd `ReadWritePaths` 精确限制到单环境目录，并启用 `ProtectProc=invisible`、
  `ProcSubset=pid`；备份加密/签名私钥不能进入 trader 进程；
- 同一账户最多运行一个写入者；仓库内的 account-UID scoped 外部租约只负责协调和
  fail-closed 门禁。跨主机自动接管还必须由唯一写代理执行 fencing token，或先
  STONITH/撤销旧 key/封禁旧 egress 并完成全账户 reconciliation；否则禁止自动接管，
  不得把 lease TTL 当作交易所侧 fencing；
- 生产 key、production 数据库和 production 状态目录不得出现在 Demo 主机环境文件中。

`demo-shadow` 账户无法做到零非 USDT 余额时，不得通过“忽略 Demo 初始资产”绕过
安全门禁；应更换子账户或先在 Demo 页面清理资产。

当前约有 1 BTC 基线资产的账户不能直接作为通用 `demo-chaos`：它会违反默认敞口
上限，并污染 flat、外部成交和 partial-fill 场景。应优先清仓；未清仓前仅可用于
contract 或明确的“已有仓位保护/恢复”演练，且必须签名固化 pre/post baseline，
不能向正式 ledger 贡献任何样本。

### 2.3 多角色评审结论与修订边界

本轮由交易安全、研究准入、运维/安全三个角色先独立审查，再交叉反驳和收敛。
仓库内已关闭的 P0 问题包括：

- ACTIVE 保护单被交易所取消/失败时，WS 回调和新 BUY 共用同一 operation lock；
  回调返回前先冻结 entries、进入 `EMERGENCY_EXIT`、持久化一次性 Page，再由安全循环
  受控退出，避免等待周期对账；
- 非终态 probe saga 由启动和周期 reclaimer 使用 fenced lease 查询事实后推进；
  `LIVE/PARTIAL/CANCELED/UNKNOWN` 不再形成永远悬挂且不进分母的“健康日”；
- Demo preflight receipt 在 trader 进程内、创建 OKX client 之前再次验证，并绑定
  live argv、UID/GID、systemd cgroup、netns、release/config/account/key/unit；
- quiet-but-healthy WebSocket 由持久 liveness sample 证明，不再要求每天必须出现
  state transition；缺采样和过大采样间隔仍记为不可观测；
- 正式告警 SLO 只接受 outbox/delivery 与带 exact artifact hash 的 provider receipt；
  每日 synthetic challenge 缺失或没有 provider receipt 会使日报 invalid；
- 日结同时冻结 raw facts 和 report；第二故障域按 exact object version 回读并重算，
  使用第四个独立 Ed25519 身份签名。最终生产 Gate 要求连续每一天都有该签名；
- epoch 的 monitor/risk/observation、Canary operator/risk 以及 bundle verifier 均按
  规范公钥 DER 指纹判重，复制同一私钥到不同路径不能伪装职责分离；
- Canary transition 绑定 exact release、strategy/bar/instruments/interval/risk
  behavior；首次启动先保持 HALTED，完成真实 UID、权限、WS/REST、保护、告警、备份
  等 post-start checks 后，再使用绑定 runtime instance/boot 的 5–15 分钟双签
  activation 开放 entries；
- Canary 运行期间 backup RPO 超限会在运行时锁存 HALTED 并 Page，不再只在启动时
  检查字符串。
- 任意晚于 startup hold 的硬故障都会推进 hard epoch；旧 activation 即使随后出现，
  也不能释放该故障。周期路径先执行风控，再尝试 Canary activation；
- probe 使用预提交的 UTC slot、交易对、方向、spread/volatility bucket；不符合
  schedule 的样本不能下单也不能进入分母；正式 schedule 必须覆盖精确 30 个连续
  UTC 日、每天精确一个 slot、在 epoch `issued_at/started_at` 前预注册，并使
  time × spread × volatility 的 16 个联合格近似均衡；
- 30 日滑点不再使用可手填常量或把 buy/exit 当成独立样本：每笔 execution 的动态
  成本由冻结 manifest 和原始 candle/notional 输入重算，再按 `probe_id` 聚类，以
  精确 30 个 DONE formal probe 的 Student-t 单侧 95% 上界验收；日报 residual
  cluster 集合必须与当天 DONE probe 集合精确相等，额外、缺失或重复均 invalid；
- 异地 backup 用户只生成签名回执，trader 运行时验签并作为唯一 SQLite 写者入账；
  独立 verifier 对 journal、monitor、alert 和 backup 四类对象逐一 exact-version
  GET 后才签署日 attestation。
- 四类 external source 公钥在 soak epoch 创建时预注册，并与 monitor/risk/
  observation 形成七个互异身份；Gate 逐日核对。journal 来源必须是签名 locator
  指向的原始 SQLite exact version，verifier 从该数据库重新导出 facts，不能接受
  自报“all_signatures_valid”的摘要替代。
- synthetic alert 与 provider/human receipt 先原子投递到文件 inbox，再由运行中的
  trader 验签并写入 SQLite；timer/import 工具不再成为第二数据库写者。
- Canary 五项 post-start check 的 schema、双层验签和 fail-closed Gate 已实现：
  正式证据必须由 transition 预绑定公钥签署，并按 URI/version/SHA/bytes 从
  Object Lock 精确回读；`runtime_started_at` 用于机器验证 safety kernel 是否在
  60 秒内可观测。12 路 production collector/signer、systemd 隔离、独立 WORM
  exact-GET/deployment verifier 与一次性 capability 工具已实现；没有真实部署、
  IAM/STS receipt 和 Object Lock readback 时仍返回 `EXTERNAL OPEN`，不能用本地
  source artifact 或测试环境变量解锁。
- 五类 post-start 机器事实的来源公钥按 check 名称预绑定进 transition；schema
  要求绑定当前 account/unit/epoch/transition/policy/target/runtime/boot。API
  metadata 还必须绑定目标 key fingerprint；backup 必须嵌入 exact-version 下载
  bytes 并本地重算 hash/长度。十二类 pre/post producer inventory 的 canonical
  hash 已进入 Demo deployment identity、Canary target 和 transition，并由 Gate
  精确比较。collector 会使用实际 systemd credential 生成 OKX V5 签名并重算 key
  fingerprint；WORM object/origin/KMS 在 inventory 冻结、version 在 capability
  manifest 冻结，并由 systemd credential 动态生成 AWS S3 SigV4，实际 reader
  access-key fingerprint 也进入签名根。position/algo 与普通订单同时比较
  REST/WS/journal 的数量、方向、状态、事件水位和 30 秒新鲜度。十二路真实外部实例及
  IAM/STS/Object Lock attestation 未交付前，production readiness 固定为 false。
- Active/Chaos preflight 和运行时必须取得独立 HTTPS broker 签发的 account-UID
  writer lease；跨主机冲突 fail-start，续租丢失会 HALT/Page。所有 REST 写请求在
  rate-limit 等待后、socket write 前重验 lease，BUY 还重验 entry/probe capability。
  broker 的单调 token 是协调身份，不宣称被 OKX 执行的 exchange-side fencing。
- Active unit 固定运行无普通 BUY 能力的 `validation_probe`；即使配置或调用层误入，
  runtime 也拒绝非 `demo_validation_probe` 来源的 BUY；probe BUY 必须在 journal
  事务中匹配 `BUY_SUBMITTING`、稳定 clOrdId、当前 lease owner/fencing token。
- backup publisher 与 restore verifier 使用不同 Unix 身份和 Ed25519 key；独立
  verifier 会 exact-version GET archive 与 manifest 原始 bytes。restore service、
  环境文件和 evidence key 均与 publisher 分离。
- provider receipt、human ACK、escalation 分别用三把预注册公钥；文件 inbox 是
  外部进程唯一写路径，trader 保持 SQLite 单写者。外部 monitor 事实同时绑定
  account UID、unit、epoch、endpoint 和事件 ID。
- backup receipt I/O/验签已移出安全循环；未保护仓位 watchdog 只读有年龄上限的
  WS mark cache，无可靠 mark 时保守视为非 dust，并将 emergency exit 放入独立线程；
  ticker/退出网络阻塞不再拖延下一次 deadline 检查。

以下项目不能靠代码评审关闭，当前统一为 **NOT_ADMITTED / EXTERNAL OPEN**：

- Gate A：两个真实 Demo 子账户/key、单机 Linux/systemd/netns/cgroup；Gate B 才要求
  第三个 Chaos 子账户和第二故障域 monitor；
- account writer 的 exchange-side fencing/STONITH、旧凭据或旧 egress 隔离，以及
  接管前全账户 reconciliation；完成前禁止跨主机自动接管；
- 真实 Object Lock COMPLIANCE、跨账号 exact-version GET、KMS/IAM deny-delete；
- Shadow 72 小时、Active burn-in 7 日、最终候选 chaos matrix 和 30 个完整 UTC clean
  day；
- WP4/WP5 的 18 个场景已统一进入 challenge/workload/native semantic inventory，
  但生产级 executor 仍全部为 `EXTERNAL OPEN`，Stage-C loader 会在读取任何 receipt
  前拒绝。仓内的 5 个 legacy repository producer、4 个外部状态 Demo actor/raw
  collector、3 个隔离 barrier test-executor，以及其余 parser/collector 积木都只用于
  开发和故障测试，不是 `EXECUTOR_SHIPPED`。allowlist
  systemd/procfs/SQLite/HTTPS/proxy collector、受控故障原语、DynamoDB 条件消费
  challenge 与签名 consumption receipt 也不能单独证明生产场景执行器已经部署；
  能力清单显式区分 `PARSER_READY`、`EXECUTOR_SHIPPED` 和每次证据运行中派生的
  `DEPLOYMENT_ATTESTED`。root-owned trust manifest 只能冻结 raw hash/bytes 与
  registrar/capability/source 公钥（`TRUST_CONFIGURED`），不能自报或提升部署状态；
- implementation inventory v2 已将 verifier source/artifact digest、严格 result
  schema、依赖闭包、security-test 原始结果、build provenance 与各 trust root 纳入
  不可变身份；native recovery bridge、同一次 evidence cut、稳定双读和
  PID/InvocationID/reconciliation generation/observer/TLS binding 也已编码并有
  fail-closed 回归。它们仍只是仓内协议与部署资产：18 个场景在取得逐场景真实
  executor、独立 systemd/IAM、deployment attestation 和 WORM exact-version 回读前
  均保持 `EXTERNAL OPEN`，不得由结构正确的本地 JSON 或测试 fixture 替代；
- Canary 的 12 路 collector/signer 与 systemd/cgroup 部署协议已实现，但尚未在
  真实隔离主机运行并取得 IAM/STS、Object Lock、deployment attestation；
  production Gate 的 readiness 因缺外部事实而固定拒绝；
- provider/human ACK 时延、真实 local/offsite RPO、空主机 RTO、主机重启和真实
  partial-fill；
- probe schedule 的实际按时执行与波动/spread 分层覆盖，以及 30 日
  动态成本残差按 probe 聚类后的 Student-t 单侧 95% 上界。

任何文档中的“仓库能力已实现”仅指代码路径和自动测试可用，不代表上述外部事实已经
发生，也不得据此签发 Canary 或生产准入。

### 3.1 评审后能力分层：为什么“代码更多了”仍不能实盘

本轮交叉评审把 Stage-C 明确拆成五个不可互相替代的证明层：

1. `PARSER_READY` 只证明固定输入可以被确定性重算，不能证明故障真实发生；
2. repository test actor/executor 只证明仓内状态机或业务边界可测试，不能证明它已被
   challenge、systemd workload、IAM、独立 source signer 和 WORM 链约束；
3. `EXECUTOR_SHIPPED` 必须同时通过逐场景语义 verifier，并绑定实际 driver、
   collector、systemd unit、IAM policy、native-frame schema 和攻击回归制品；
   文件存在、64 位 hash 或测试函数名字本身都不能升级状态；
4. `DEPLOYMENT_ATTESTED` 只能由当前 evidence run 对 challenge、capability、
   workload、source-role 原始字节和最终快照全部复验后派生，配置文件不能声明；
5. 72 小时、7 日、30 日以及真实 Object Lock/IAM/第二故障域是时间与外部事实，
   无论单元测试数量多少都不能由仓库代码补写。

因此当前改进的实际价值是：故障语义更清楚、测试边界更接近真实、误准入更难；它没有
改变结论——当前版本可以继续模拟盘验证，但还不能进入小资金实盘或无人值守生产。

## 4. 需要补齐的开发包

### WP0：发布级 Demo contract evidence

目标：把已通过的交互式 contract 升级为可绑定发布身份的证据。

开发：

- 将 contract evidence 升级为 v2，加入：
  - 完整 Git commit、tree hash、workspace clean；
  - source manifest SHA-256；
  - 脱敏配置 hash；
  - OKX account UID；
  - API domain、simulated 标志、脚本版本；
  - UTC 起止时间、contract run ID 和 fixture SHA-256；
- 增加 `scripts/verify_demo_contract.py`，离线复验 schema、hash、环境、cleanup 和
  fixture 引用关系；
- 使用 detached manifest/envelope 记录 evidence bytes SHA-256、exact object
  version ID、retention 和签名；禁止把“自身 SHA-256”写入被哈希主体；
- 原始 evidence 上传跨账号、启用 Object Lock compliance retention 且禁止
  `DeleteObjectVersion` 的私有对象；脱敏 fixture 放入稳定测试目录；
- 独立 verifier 使用自己的只读凭据按 exact version GET，重新计算 evidence/fixture
  hash、验证 retention 和签名后才能确认；
- 目标提交、配置或账户变化后 contract 必须重跑。

验收：

- 在干净已提交工作树上运行；
- verifier 返回 0；
- evidence 的 commit/config/account 与待观察环境一致；
- immutable object URI、version ID、retention、SHA-256 和 detached signature
  可由独立身份回读验证。

### WP1：Demo 专用部署与 preflight

目标：不复用需要生产准入签名的 production unit，同时保持相同的 systemd hardening。

交付：

- `deploy/demo/config.shadow.yaml.example`
- `deploy/demo/config.active.yaml.example`
- `deploy/demo/config.chaos.yaml.example`
- `deploy/systemd/okx-quant-demo-shadow.service`
- `deploy/systemd/okx-quant-demo-active.service`
- `deploy/systemd/okx-quant-demo-chaos.service`
- `deploy/systemd/okx-quant-demo-watchdog@.service`
- `deploy/systemd/okx-quant-demo-backup@.service/.timer`
- `deploy/systemd/okx-quant-demo-evidence-close@.service/.timer`
- 三环境独立 env、logrotate/journald、monitor agent 与 backup 配置模板；
- `scripts/demo_preflight.py`

`demo_preflight.py` 必须 fail closed 检查：

- `okx.simulated=true`、`production.environment=demo`；
- API 鉴权、账户 UID、Shadow 精确 Read-only、Active/Chaos 精确 Read + Trade；
- key fingerprint、数据库、lock、heartbeat、metrics port、Unix UID、release path 和
  network namespace 不与其它环境复用；
- Shadow 账户没有非 dust 基础币、挂单或 algo；
- Active 账户没有不可解释挂单/algo/持仓；
- 时钟偏差 ≤1 秒；
- journal identity、schema 和 `PRAGMA integrity_check`；
- public/private/business WS 均可在 30 秒内 READY；
- 环境文件 owner/mode、祖先目录、符号链接、精确 `ReadWritePaths`、`/proc` 隔离；
- 日志、状态、备份目录权限和磁盘/inode 余量满足门槛；
- account-UID scoped 单写者租约不存在冲突。

Preflight 成功后输出绑定 release/config/account/key/unit/精确 live argv 的短效
receipt；receipt 为 `root:<目标 trader group> 0640`，目标进程可读但不可写。
systemd `ExecStartPre` 先复验，`main.py` 在创建 OKX client 前再次核对 receipt、实际
UID、service cgroup 和 netns inode，随后才允许产生正式 facts；最后再检查
`/readyz`。重复运行 preflight 必须幂等；任一串线、余额或状态异常都以非零退出，
不能手工跳过后直接启动。

### WP2：持久化 WebSocket 与运行可用性证据

目标：Prometheus 瞬时值之外，形成可由 SQLite 日报告重算的 durable 事件。

增加以下 durable events：

- `websocket_state_transition`
  - channel、old/new state、generation、timestamp；
- `websocket_subscription_ready`
  - channel、connect/subscribe latency；
- `websocket_recovery_completed`
  - disconnect duration、REST baseline duration、generation、safe；
- `exchange_fact_consumed`
  - source、channel、generation、event sequence、ordId/clOrdId/algoId、probe ID、
    dedupe result；用于区分 REST 投影与真实 private/business WS 消费；
- `runtime_readiness_transition`
  - old/new mode、原因、持续时间；
- `runtime_heartbeat_sample`
  - account、unit、epoch、runtime instance、boot、PID、mode、healthy；
- `alert_delivery_sample`
  - event ID、enqueue、attempt、HTTP ingestion、provider received、human ack 时间；
- `backup_slo_sample`
  - snapshot start/end、integrity、bytes、offsite publish/readback、exact version；
- `process_resource_sample`
  - boot ID、PID、cgroup、RSS、FD、threads、DB/WAL bytes、磁盘和 inode；
  - WAL checkpoint log/checkpointed/backlog frames、page size、backlog bytes 和
    距离最近一次完整 checkpoint 的年龄；
- `clock_quality_sample`
  - chrony sync/max error、OKX request RTT midpoint 校正后的时钟偏差。

约束：

- 不把 UID、API key、签名或完整原始 WS 帧写入 metrics label；
- channel/inst/state 使用有界 label；
- WS quiet channel 以协议 ping/pong 和连接状态判断活性，不以“无订单消息”判 stale；
- 自管 ping 必须记录 pong RTT/last-pong；不能用“最后一条业务消息时间”代替连接活性；
- READY 必须仍由同一 generation 内的 WS + REST baseline fence 决定；
- generation 只能在 `CONNECTING` 时严格加一；每个 READY 恰好对应一个同 channel、
  同 generation 的 subscription fact，每个完整断线 episode 恰好对应一个 safe
  recovery fact，孤儿、重复、缺失和持续时间不闭合均使日报 invalid；
- heartbeat mode 必须与 durable readiness transition 在该采样时刻推导出的 mode
  一致；日报从跨日 boundary 重算 READY 比例、最大非 READY 时段和 hard transition；
- `PASSIVE` checkpoint 返回 `busy=0` 仍不等于完整完成；只有
  `checkpointed_frames == log_frames` 才能刷新完成时间，持续 backlog 必须进入
  Warning/Page 和日报 Gate。
- 资源原始数据由 host/cgroup agent 每 30–60 秒外采，SQLite 只保存至多每 5 分钟的
  rollup，避免观测行为本身制造 WAL 无界增长。

将 `scripts/slo_report.py` 升级为 v2，新增：

- 实际可观测秒数和最大证据缺口；
- 每频道连接可用率、断线次数、最大断线、恢复 p50/p95/p99/max；
- 对账期望次数、实际次数、成功率、最大完成间隔、自动修复与 unresolved；
- 启动/重启次数和恢复时长；
- heartbeat、readiness、Page delivery、backup RPO、组件恢复 round-trip 与独立
  empty-host RTO；
- RSS/FD/DB/WAL 增长趋势；
- Shadow intents、Active probe、保护和滑点样本数。

必须同时升级：

- `scripts/production_gate.py record`，只接受 exact SLO v2 schema 和 policy hash；
- `DemoObservationLedger` v2、`consecutive_clean_days`、`AdmissionGate`；
- demo observation anchor 的签名 claims；
- `activate_release.py` 和正式 Gate 的版本拒绝/迁移测试。

验收：日报告完全由 durable facts 重算，不接受命令行手填覆盖；正式 epoch 一律拒绝
v1、未知字段、缺失字段、零预期但无采样、重复或孤儿事件。失败/超时必须成为 breach
样本，不能因为没有成功事件而显示为 0 秒通过。

### WP3：生产路径 Demo 小额探针

现有 `demo_contract.py` 直接验证 OKX adapter，不经过长期运行中的
`ProductionRuntime → ExecutionCoordinator → ProtectionManager → Reconciler` 全链。
需要增加受限的 `demo-probe` 控制命令。

硬限制：

- 只允许 `environment=demo && shadow_mode=false`；
- 只允许 allowlist 中的 `*-USDT`；
- 每次名义金额 5–10 USDT；10 USDT 是不可由 YAML/env/CLI 放大的代码常量，并由
  发布 source hash、数据库约束和边界测试共同保证，不能称为 Python“编译期”限制；
- 正式 epoch 每账户每天精确 1 次；同一时刻最多一个 probe，账户级未决
  BUY、已有非 probe 仓位、普通单或 algo 存在时禁止启动；
- Active 只运行确定性的 validation-probe 策略；正式 epoch 禁止其它策略入口与 probe
  共享账户，以免突破次数、敞口和样本分母；
- 必须经过正常持久化 intent、原子风控、WS 投影、保护和联合对账；
- 退出必须通过 `ExitCoordinator` 的 exit lease 协调保护撤销和市价退出，不能由
  probe 脚本先裸撤保护再自行 SELL；
- intent/event 标记 `source=demo_validation_probe`，与策略交易分开统计。

新增 durable `probe_runs` saga，至少包含：

| 状态 | 含义与恢复动作 |
|---|---|
| `PREPARED` | 已占用 `(account_uid, UTC_day, slot)` 唯一配额，尚未产生写操作 |
| `BUY_SUBMITTING/BUY_UNKNOWN` | 先按稳定 clOrdId 查询 WS/REST/历史订单，禁止重放 BUY |
| `BUY_FILLED` | 根据累计成交和手续费确定可保护数量 |
| `PROTECTING/PROTECTED` | 按稳定 algoClOrdId 查询或恢复，禁止建立第二张保护 |
| `CLEANING` | 通过 exit lease 恢复撤保护/退出/最终对账 |
| `DONE` | cleanup 和余额 delta 已验证，只允许可证明子 lot 尘埃 |
| `MANUAL_REVIEW` | 事实冲突或超时；保留风险预留、HALTED、Page，禁止新 BUY |

要求：

- stable `probe_id → clOrdId/algoClOrdId`，数据库唯一键
  `(account_uid, UTC_day, slot)`；
- 带 fencing token 的 lease/超时 reclaim，崩溃后可重新领取未完成 saga；
- 每一步必须先落 durable state，再执行外部副作用；
- reclaim 后先查询交易所事实，再推进状态，不允许重放写请求；
- 在每个 POST 前/后、ACK 前/后、保护 ACTIVE 和 cleanup barrier 做确定性崩溃测试。

UNKNOWN 必须明确分成三条验收分支：

1. 明确拒绝且交易所无单：`REJECTED` 并释放预留；
2. 已接受但 ACK 丢失：按 clOrdId/WS/REST 找回，绝不重复 BUY；
3. 无法裁决或事实冲突：保留预留并进入 HALTED/MANUAL_REVIEW/Page。

不能把 UNKNOWN 理解成“立即 cleanup”：在裁决前禁止新 BUY、盲目 cancel、重复 SELL；
解析为已成交后才建立保护并受控退出。

Shadow 环境只生成同等输入的 `SHADOW_NOT_SUBMITTED` intent，用于确认“零交易所写”。

验收：

- Shadow 连续 72 小时交易所订单数为零；
- Shadow 的 API 权限证据为 Read-only，写端点审计尝试数为零；
- Active 每次 probe 都产生带 source/generation/probe ID 的 WS order/fill/algo 消费事实；
- clOrdId 审计链完整；
- 保护 ACTIVE ≤10 秒；
- cleanup 后只允许可证明的子 lot 尘埃；
- 任一 barrier 重启后 saga 均收敛，重复 BUY 数为零。

### WP4：真实 WebSocket 与联合对账演练

在 `demo-chaos` 执行，不能污染正式 30 日 ledger。

WebSocket 场景：

1. 通过每频道独立的 localhost fault proxy/netns connection mark 分别阻断
   public、private、business WS；三个连接共用 OKX host 时不能使用粗粒度 host
   `iptables` 冒充分频道故障；
2. 保持 REST 可用，验证 ≤20 秒进入 DEGRADED/HALTED；
3. 断线期间 BUY 必须为零，退出语义仍可用；
4. 恢复网络后必须在同一 WS generation 内完成 REST baseline 才能 READY；
5. 在订单部分成交时断线，重连后累计成交不得重复；
6. 外部创建普通单/algo，使用 `exchange_fact_consumed` 证明 private/business WS
   确实被消费，而不是只靠 REST 响应或周期对账。

真实部分成交不能依赖 5–10 USDT BTC 市价单“碰巧”发生。演练前必须写明可重复的
限价/数量/流动性方案，并按每个 `accFillSz` delta 证明保护 resize、断线恢复和成交
幂等。若 OKX Demo 无法稳定制造，就把“真实部分成交”保留为未验证外部条件；不得用
FakeExchange 结果替代真实 WS 证据。

联合对账场景：

1. 外部创建 pending BUY：导入并冻结新增风险；
2. 外部成交：导入 order/fill/position，非 dust 仓位要求保护；
3. 外部取消保护单：确认取消后立即冻结 entries、进入 EMERGENCY_EXIT 并 Page，
   默认通过受控退出消除敞口；不能等待 30 秒周期对账后再重建；
4. 冻结余额、available=0/total>0：不得误判为零仓；
5. 制造 clOrdId 冲突：进入 MANUAL_REVIEW，不自动重下；
6. 交易所短暂 5xx/429：读请求退避，写请求保持 UNKNOWN 语义。

未来若决定支持“外部撤保护后重建”，必须作为单独能力评审：只有取消已确定、
仓位/SELL 事实一致时允许一次幂等重建，并且从失保护起 10 秒内未 ACTIVE 就退出。
成功重建只计 chaos 恢复证据；正式 soak 发生外部撤保护仍是 invalid/reset。

每个演练必须输出 JSON，并通过 detached signature 上传到 Object Lock WORM；本地
“拒绝覆盖同名文件”不能称为 write-once：

- commit/config/account；
- 故障开始与恢复时间；
- 预期状态迁移和实际状态迁移；
- 对账 run ID、差异、修复和 unresolved；
- Page event ID 与接收时间；
- 演练后订单、algo、仓位、余额和 journal 完整性。

### WP5：真实重启与崩溃恢复演练

在 production 同构 Linux/systemd 主机和 `demo-chaos` 账户执行：

| 场景 | 必须证明 |
|---|---|
| flat 状态 SIGTERM | 正常停止、无残留锁、重启 ≤60 秒 READY |
| flat 状态 SIGKILL | WAL 完整、startup reconciliation 收敛 |
| BUY intent 持久化后/POST 前退出 | intent 安全 REJECTED，交易所无订单 |
| POST 后/ACK 落库前退出 | 按 clOrdId 解析 UNKNOWN，不重复 BUY |
| fill 后/本地投影前退出 | REST/WS 恢复累计成交一次，立即检查保护 |
| OCO ACTIVE 时进程死亡 | 交易所保护继续存在，watchdog Page |
| WS 断线时重启 | 未建立同 generation baseline 前不得 READY |
| backup/DB 损坏 | 保持 HALTED，从已验证备份恢复，禁止空库替代 |

故障证据分两类：

- exact release 黑盒证据：netns/fault proxy、systemd SIGTERM/SIGKILL、DB/磁盘和
  主机重启；必须绑定正式候选 artifact；
- instrumented test-only 证据：POST/ACK 等内部确定性 barrier；构建必须有不同
  artifact identity，不能冒充 exact release。

不得靠随机 `kill -9` 猜测内部窗口，也不得把 fault hook 放入可由 production
配置启用的路径。发布 manifest 必须证明正式 artifact 不含可激活的 test hook。

验收：

- 所有场景无重复 BUY；
- 非 dust 仓位始终有交易所 ACTIVE 保护或进入 emergency；
- startup reconciliation max ≤60 秒；
- 数据库 integrity 为 `ok`；
- 任一不确定状态保持 HALTED/MANUAL_REVIEW；
- 任一影响 runtime/config/schema 的修复都会使相关演练失效；必须在最后一次
  release freeze 后对最终候选重新执行完整黑盒 matrix。

### WP6：监控、告警和外部证据

交付：

- `deploy/monitoring/prometheus-rules.yaml`
- `deploy/monitoring/grafana-dashboard.json`
- 外部 synthetic monitor，不能与 trader 同进程；
- Page 接收器或 Alertmanager 路由；
- `scripts/demo_soak_status.py`。

metrics 默认只监听 `127.0.0.1`。外部观测应通过本地 agent `remote_write` 或受控
mTLS proxy 输出，不能直接把 Python metrics HTTP 暴露到公网。外部 monitor 必须位于
第二故障域，使用独立凭据，并同时监控 host、service、provider、evidence-close timer
和 backup freshness；缺少预期 dead-man signal 本身必须 Page。

P0 Page：

- 有仓位/未决 BUY 时 heartbeat >20 秒；
- 任意非 dust 仓位无 ACTIVE 保护 >10 秒；
- UNKNOWN BUY >30 秒；
- reconciliation failed/unresolved；
- DB 不可写、损坏、磁盘或 inode 低于阈值；
- WS 连续错误预算耗尽；
- alert outbox 无法投递；
- backup RPO >5 分钟。

P1 Warning：

- 单次 WS 重连；
- reconciliation 自动修复；
- API 错误率或延迟升高；
- snapshot/market data 接近 stale；
- RSS、FD、DB/WAL 增长异常；
- 滑点接近批准上限。

告警演练验收：

- 每个事件使用稳定 event ID/idempotency key，投递器持久化 attempt、HTTP ingestion、
  provider received、human ack 和升级时间；
- P0 从故障发生到 `provider_received` ≤60 秒；P1 ≤5 分钟；
- human ack/无人响应升级使用单独的值班 SLA，不能用 webhook HTTP 2xx 冒充人工确认；
- 投递采用持久重试、指数退避和 DLQ；
- 相同持续事件去重，恢复后可重新 Page；
- trader、watchdog、monitor 三者任一死亡不能同时消除全部告警能力，且不能全部依赖
  同一个 webhook/SaaS 故障域。

资源门槛必须预先机器化，不能靠“看图判断是否失控”：

- host/cgroup 每 30–60 秒采样，journal 每 5 分钟 rollup；
- RSS 在 MemoryHigh 的 70% Warning、85% Page，MemoryMax/OOM 为 hard breach；
- FD 在 `LimitNOFILE` 的 60% Warning、80% Page；
- 明确 `TasksMax`、`LimitNOFILE`、`OOMPolicy`、`StartLimit*` 和 CPU throttle 指标；
- DB/WAL、磁盘 bytes/inodes 同时使用绝对上限、checkpoint age 和预注册 slope；
- 每个样本绑定 boot ID、PID、release/config identity。

备份 SLO 拆为：

1. 进程故障下 SQLite journal RPO = 0；
2. 独立本地一致性快照的已验证可恢复点年龄 ≤5 分钟；
3. 异地加密、签名并按 exact version 回读成功的可恢复点年龄 ≤5 分钟；
4. empty-host 完整恢复每月演练，端到端 RTO <30 分钟；日常 exact-version
   component restore 只能证明组件可读/可恢复，不能替代此 RTO。

当前 5 分钟定时器无法证明 5 分钟 RPO。初始实现目标为本地快照每 60 秒、异地发布
每 2 分钟，并以“调度间隔 + P99 完成时间 ≤5 分钟”验收；若压测证明不可行，只能经
独立风险审批修改 offsite SLO，不能静默放宽。

### WP7：每日证据与 30 日 ledger

正式开始前先生成由独立 monitor 和风险方共同确认的 `soak_epoch`：

- `soak_epoch_id`、UTC `started_at`、policy hash；
- `release_identity`：commit/tree、source manifest、依赖、解释器；
- Demo `deployment_identity`：release、完整脱敏配置、launch、account UID、
  environment、unit、host image、key fingerprints；
- strategy/bar/instruments/interval、风险参数、probe schedule；
- SLO v2 schema/policy hash、监控/签名公钥指纹。

Shadow 和 burn-in 使用 `phase=shadow|burn-in`，不得计入正式 epoch 的天数或样本。

每日 UTC 日结顺序：

1. 从只读数据库生成 `slo-report-v2-YYYY-MM-DD.json`；
2. `demo_soak_status.py` 复核当日硬门槛；
3. 上传报告、日志摘要、metrics snapshot 和演练记录到 versioned object storage；
   bundle 使用字段 allowlist 和 secret scanner，禁止包含 API key/secret/passphrase、
   完整环境文件、签名私钥或未经脱敏的原始 WS 帧；
4. 使用跨账号 Object Lock compliance retention、deny `DeleteObjectVersion` 和 KMS；
5. 独立 monitor 用自己的只读凭据按 exact version GET，验证 bundle manifest、
   component hashes、bytes SHA-256、retention 和签名；
6. 独立 monitor 在当天或次日签署包含 previous hash、epoch、phase/status、policy
   hash 和完整硬指标的 observation anchor；
7. `production_gate.py record` 复验 SLO v2 后追加 hash-chain ledger；
8. 将当日状态明确写为 `clean`、`invalid` 或 `burn-in`，附 `reason_codes`；
   invalid 行同样必须 append-only 保存，禁止跳过坏日或人工改写。

正式 30 日只接受：

- 同一 `soak_epoch_id` 与 `release_identity`；
- 同一 Demo `deployment_identity`、account UID、策略、bar、交易对、interval、风险参数
  和 probe policy；
- 每个 clean day 固定为完整、互不重叠的 UTC `[00:00, 24:00)` 86,400 秒；
- 每频道 WS 不可用总计 ≤432 秒（可用率 ≥99.5%），单次未恢复断线 ≤60 秒；
- 证据不可观测总计 ≤432 秒，最大连续证据缺口 ≤300 秒；缺口一律计入不可用分母；
- unexplained reconciliation mismatch = 0；
- 每日精确 1 个完整 probe；30 日合计精确 30 个独立 probe saga、30 个独立
  protection lifecycle，以及 buy/exit 合计 ≥60 个 execution slippage 样本；
- attempts、confirmed fills、UNKNOWN、timeout、失败和缺失样本全部进入 denominator；
- probe/保护样本关联完整率 = 100%，保护失败/UNKNOWN/超时率 = 0；
- protection 聚合 p95 ≤3 秒、全样本 max ≤10 秒；p99 始终报告，但只有独立保护样本
  ≥300 时才作为统计门槛，不能用 n≈60 的 p99 重复冒充 max；
- 每笔 slippage max ≤批准上限；probe schedule 在 epoch 前冻结并均衡覆盖交易对、
  方向、四个 UTC 时段和至少两档波动/spread；动态成本逐笔重算，buy/exit 残差按
  `probe_id` 聚类，以 30 个独立 cluster 的 Student-t 单侧 95% 上界验收，禁止把
  同一 probe 两条腿伪装为两个独立样本；
- reconciliation 成功率 ≥99.9%，最大完成间隔 ≤90 秒；
- local/offsite 已验证可恢复点年龄均 ≤5 分钟；
- 无重复 BUY、未清理订单、未解释余额或不可恢复 MANUAL_REVIEW。

只有完整 24 小时 clean day 才计数。≥20 小时但不足上述门槛的窗口可以登记
`burn-in` 或 `invalid`，不能登记 `clean`。

重置语义：

- release/config/account/strategy/bar/inst/interval/key/unit 等冻结身份变化：关闭旧
  epoch 并创建新 epoch，连续天数从 0 开始；
- 缺日、证据失真、重复 BUY、unresolved、保护/cleanup/滑点/RPO/WS/证据缺口硬限
  失败、不可恢复 MANUAL_REVIEW：追加 `invalid` 行并打断 streak，下一 clean day
  从 1 开始；
- 预算内瞬时重连、P1 Warning 或发生在隔离 Chaos 环境的计划演练不自动重置；
- 以删除数据库、删除坏日、修改 ledger 或忽略余额的方式“修复”会使整个 epoch
  失效。

### WP8：Demo → Canary 身份迁移与机器约束

Demo ledger 不能直接伪装成 Canary/Production 身份。当前最终 Gate 要求 evidence
的 account/config/environment 等于实际启动身份，而 Demo 到真实资金必然改变
`simulated`、account UID、key 和部分风险配置。因此必须拆分：

- 可迁移的 `release_identity`：exact artifact/source、依赖、解释器、策略行为和
  安全不变量；
- 必须重新验证的 `deployment_identity`：account UID、`simulated=false`、API
  域名/权限/IP 白名单、unit、host、目录、key fingerprint、资金和风险限额。

新增签名 `demo_to_canary_transition`：

- 绑定 Demo epoch head、release identity、目标 Canary deployment identity；
- 只允许白名单差异，release 行为代码变化禁止迁移；
- 独立列出必须在 Canary 首次启动前/后重验的项目；
- 不能让 Demo 30 天自动授权 full production。

Canary 必须有机器可读、短效、不可自动晋级的签名 policy：

- account/key fingerprint、expiry、允许交易对；
- 单笔名义、订单频率、并发仓位、总敞口；
- 单笔损失、日损、回撤、滑点；
- 自动 halt/flatten、人工升级和 rollback owner；
- 独立 operator/risk approver 签名。

实现时必须解决当前 runtime 只接受 `demo|production`、最终 evidence 又允许
`canary|production` 的身份矛盾：可以引入 `canary` runtime environment，也可以把
Canary 定义为 `production` 环境下的强制 canary policy，但只能保留一种无歧义语义，
并提供 30 日 Demo → Canary → 仍不能自动 Production 的端到端 Gate 测试。

### 开发排期、依赖与责任

| 优先级 | 工作包 | 主责角色 | 依赖 | 预计工程量 |
|---|---|---|---|---:|
| P0 | WP0 发布级 contract evidence | 开发 + 安全复核 | 干净提交、Demo key、WORM | 1–2 人日 |
| P0 | WP1 Demo 部署/preflight | 运维 + 开发 | 三个子账户、隔离主机/namespace | 2–3 人日 |
| P0 | WP2 durable WS/SLO v2 | 开发 | schema/event/Gate 评审 | 3–4 人日 |
| P0 | WP3 durable production-path probe | 交易安全开发 | WP0、WP2 | 3–5 人日 |
| P1 | WP4 WS/联合对账演练 | 开发 + 运维 | WP1–WP3、干净 chaos 账户 | 2–3 人日 |
| P1 | WP5 重启/崩溃恢复 | 开发 + 运维 | WP1–WP3、两类 fault evidence | 2–3 人日 |
| P1 | WP6 监控/外部告警 | 运维 | WP2、第二故障域接收器 | 2–3 人日 |
| P0 | WP7 日结、epoch 与 Gate | 开发 + 风险复核 | WP0、WP2、WP6 | 2–4 人日 |
| P0 | WP8 Demo→Canary transition | 开发 + 风险复核 | WP7、Canary policy 决策 | 2–3 人日 |

串行合计约 19–30 人日；部分工作可以并行，按一个主要开发者和一个兼职运维协作估算
为 15–25 人日。关键路径为
`WP0/WP1/WP2 → WP3/WP7 → 72h Shadow → 7d burn-in → release freeze 后重跑
chaos matrix → 30d soak → WP8`。

### 当前实施状态（2026-07-29）

| 工作包 | 仓库能力 | 尚需真实取得 |
|---|---|---|
| WP0 | v2 release/config/account identity、detached 双对象 manifest、exact-version verifier | 正式候选重新 capture、WORM 上传与独立签署 |
| WP1 | Shadow/Active/Chaos 配置、systemd、netns、preflight、分角色 Unix 身份/目录；Gate A preflight 默认严格校验 Shadow+Active，Chaos 可显式加入 | Gate A 的两个独立 Demo 子账户/key 和 Linux 主机部署；Gate B 再要求 Chaos 与第二故障域 |
| WP2 | durable WS/consumer/recovery/readiness/heartbeat/clock/resource facts；严格 generation、subscription/recovery 关联；完整 checkpoint/backlog 事实；SLO report v2 | 真实 72h/7d/30d 时间序列 |
| WP3 | durable `probe_runs` saga、稳定 ID、saga fenced lease/capability、启动/周期 reclaimer、UNKNOWN 恢复、正式 30 日每日精确一单及联合分层 schedule | Active Demo 每日实际 probe；按 epoch 前预注册 UTC×spread×volatility strata 执行并形成覆盖证据 |
| WP4/WP5 | 18 项已统一进入不可变 inventory、challenge/workload、逐场景 semantic verifier 与 build provenance 模型；5 个 legacy repository producer、3 个 barrier test-only harness 和 4 个 Demo actor 都不会被提升为 production producer，18 项生产状态均为 `EXTERNAL OPEN` | 逐场景交付并部署 production executor/live bridge；绑定 registrar/capability/source、独立 systemd/IAM、fleet/deployment attestation 与 WORM exact-version readback；在最终 freeze 候选和隔离 Chaos 环境实跑完整矩阵 |
| WP6 | Prometheus/Grafana、durable alert lifecycle、file-drop 单写者导入、五路 dead-man、周期 exact component restore、独立月度 empty-host RTO Gate | 第二故障域、真实 ACK/RPO 与月度空机 RTO |
| WP7 | 双签 epoch、四类来源公钥预注册、原始 SQLite 重建、完整 UTC 日结、Object Lock exact-version 独立重算、append-only v2 ledger/gate | 真实第二故障域/IAM/WORM 与连续 30 个 clean day |
| WP8 | `production+canary` 唯一语义、双签 transition、≤6h policy、七项 pre-start/五项 post-start 严格 schema、12 路 collector/signer/systemd、冻结 executable/request/WORM locator、独立 IAM/WORM/deployment 四权、不可绕过的 external-readiness Gate、reserve→approve→consume、运行时 backup RPO 与 hard-epoch 防旧令牌释放 | 在真实隔离主机配置并运行 12 路实例，取得 IAM/STS、Object Lock exact-version 与 deployment attestation；完成 30 日后再由独立人员/机器来源签发并执行 Canary |

详细操作命令见 `DEMO_OPERATIONS_RUNBOOK.md`。上表“仓库能力”只表示实现与测试就绪，
不表示对应外部门槛已经通过。

## 5. 分阶段执行与退出门槛

### Stage A：开发补齐，15–25 人日

完成 WP0–WP3、WP6–WP8 的仓内协议与门禁；把 WP4/WP5 全部 18 项统一纳入不可变
implementation inventory，并将当前 13 个 `PARSER_READY` 场景补齐为通过语义 verifier
的 production executor；同时在真实环境部署 WP8 的 12 路
Canary producer、IAM 和
WORM/deployment verifier 后，才具备正式执行 Stage C/E 的能力。缺失能力或外部
证据保持 `EXTERNAL OPEN`，不得用人工 receipt 替代。

退出门槛：

- 干净提交 Linux CI 对完整、不可漏项 test inventory 全绿；
- Demo contract v2 绑定提交/config/account；
- 三环境 launcher/preflight/systemd/watchdog/backup/evidence-close units 可用；
- durable probe saga、SLO/Gate v2、soak epoch 和 WORM 独立复验可用；
- Shadow Read-only 与 Active/Chaos 能力隔离检查通过；
- Chaos 故障域不会影响 Active。

### Stage B：Shadow 预热，连续 72 小时

运行 `demo-shadow`：

- 交易所写请求必须为零；
- public/private/business WS 和周期 REST 对账持续工作；
- 至少执行一次 WS 网络阻断和一次进程重启；
- 决策、风控拒绝、K 线去重和资源趋势可审计。

退出门槛：

- 72 小时内无交易所订单；
- Shadow write endpoint attempt = 0，API 权限持续为 Read-only；
- 0 unexplained mismatch；
- WS 重连和 startup recovery 均满足 SLO；
- 资源绝对值、slope、OOM/FD/thread/DB/WAL 门槛全部通过。

### Stage C：Active Demo burn-in，连续 7 天

运行 `demo-active`，每天精确 1 次小额 probe；所有破坏性演练仍在
独立故障域的 `demo-chaos`。

退出门槛：

- ≥7 个完整 probe saga、≥7 个保护生命周期和 ≥14 个 buy/exit 滑点 execution；
- UNKNOWN 三分支和逐 barrier 重启测试通过；
- cleanup、对账、Page、备份和 SLO v2 日结连续通过；
- 至少完成 WP4、WP5 的全套演练；
- 固定 18 项目录必须齐全：5 项由受控 exact-release adapter 自动执行，另外 10 项
  必须由真实独立 driver 产生 raw events 并由 parser 重算 transition/Page/
  reconciliation/postcondition，3 项必须来自正式 instrumented barrier producer；
  raw source 由第二故障域 exact-version GET 并校验 hash/bytes/Object Lock/KMS。
  当前后 13 项均为 `EXTERNAL OPEN`；仓内 Demo actor/test-executor 不改变此状态，
  production loader 会在读取 receipt 前失败，
  因而此退出门槛尚不可满足；
- 修复所有 P0/P1 后重新冻结 release/config；
- 所有受修复影响的 chaos/fault 证据绑定最终冻结候选重新执行，旧证据失效。

### Stage D：正式 30 日 soak

签署 `soak_epoch`，冻结 release/deployment/account/strategy/probe/SLO policy，开始
signed ledger。期间不在 Active 账户或故障域做 chaos。

退出门槛：

- 连续 30 个 clean day；
- 所有第 4 节硬指标由 SLO/Gate v2 强制通过；
- 30 日汇总报告和 ledger head 可重放验证；
- Shadow/burn-in/invalid 行和样本均未被计入；
- RELEASE_CHECKLIST 的 WS、对账、恢复、告警、备份、环境隔离项有证据链接。

### Stage E：独立评审与 Canary 决策，2–3 个工作日

由开发、运行、风险三方分别审阅：

- 开发：代码、schema、缺陷与修复历史；
- 运行：Page、RTO/RPO、runbook 和值班记录；
- 风险：敞口、单笔损失、日损、滑点和停止条件。

只有三方签署、WP8 transition 验证通过且其它量化/研究门槛同时满足，才签发短效、
机器可执行的极小资金 Canary policy。Canary 不得自动晋级 Production。

## 6. 证据矩阵

| 目标 | 自动证据 | 真实环境证据 | 最终 Gate |
|---|---|---|---|
| WS 长连/重连 | replay tests | durable transition/consumer facts + chaos report | 24h/99.5%/≤60s |
| 联合对账 | reconciliation tests | external order/fill/algo drill | 0 unexplained |
| Probe 幂等 | barrier/recovery tests | durable saga + exact clOrdId audit | 0 duplicate BUY |
| 重启恢复 | test-only barriers + runtime tests | exact release systemd matrix | startup ≤60s |
| 保护闭环 | protection tests | 独立 lifecycle + 全 attempt denominator | p95≤3s/max≤10s |
| 监控告警 | ops tests | provider/human timestamps + dead-man | provider≤60s |
| 备份恢复 | restore tests | exact-version round-trip + empty host | RPO≤5m/RTO<30m |
| Shadow 零写 | shadow unit tests | Read-only scope + write-attempt audit + history | 72h zero writes |
| 长期稳定 | SLO/Gate v2 + epoch tests | 30 个完整 UTC signed clean days | streak≥30 |
| Demo→Canary | identity transition tests | Canary pre/post deployment checks | signed policy |

## 7. 当前可直接执行的外部任务

仓库能力就绪后，按优先级执行：

1. Gate A 建立 `demo-shadow`、`demo-active` 两个隔离子账户和 key；Shadow 必须
   Read-only；按需增加 `demo-chaos`，但 Gate B 才要求完整独立故障域；
2. 在干净候选 release 上重新生成并独立签署 WP0 contract evidence v2；
3. 在单台 Linux 主机安装 Shadow/Active 两套 systemd/config/preflight/watchdog/
   backup/evidence-close；Gate B 再增加 Chaos 和第二故障域组件；
4. 完成 72 小时 Shadow 后，再开始 7 天 Active burn-in；
5. 修复 burn-in 发现的问题并冻结 release/config；
6. Gate A 在停止 Active writer 后执行 6 项核心故障；Gate B 再用最终候选重跑完整
   18 项 black-box matrix；
7. Gate A 通过后由双人签署 Gate C 短效小资金 Canary policy；Gate B 才创建正式
   soak epoch 并开始连续 30 个完整 UTC clean day；
8. 30 日与其它生产准入门槛只用于 full production，不是 Gate A 的前置条件。

当前最先需要解决的外部前置条件是：准备一个没有约 1 BTC 基线资产的独立
`demo-shadow` 子账户和一个可用于 flat/partial-fill 场景的干净 `demo-chaos`
子账户。当前账户在清仓前只保留为 contract 或已有仓位保护/恢复演练账户。

## 8. 多角色评审关闭矩阵

| 评审发现 | 修订决定 | 落点 |
|---|---|---|
| Shadow 零写但持有 Trade Key | 改为 Read-only + 写端点审计/deny | §3、WP1/WP3 |
| Chaos 可能污染 Active | 独立故障域、Unix/network/release/credential 隔离 | §3、WP1 |
| Probe 重启后可能卡死或重复 BUY | durable saga、stable ID、lease/fencing、逐 barrier 恢复 | WP3/WP5 |
| SLO v2 未进入最终 Gate | 同步升级 report/anchor/ledger/gate/activate_release | WP2/WP7 |
| burn-in 可混入 30 日 | `soak_epoch + phase + status + reason_codes` | WP7 |
| 20 小时窗口可隐藏停机 | clean day 固定完整 UTC 24h，缺口进入分母 | WP7 |
| 小样本 p99 与 max 重复 | p95/max 为硬门；p99 在 n≥300 后才作统计门 | WP7 |
| 外部撤 OCO 的“重建”与实现冲突 | 默认立即冻结和受控退出；重建需单独评审 | WP4 |
| 5 分钟 timer 不能证明 5 分钟 RPO | 缩短 cadence，按完成且验证的恢复点计龄 | WP6 |
| Versioning/write-once 不等于不可变 | Object Lock、deny delete、detached signature、独立 GET | WP0/WP7 |
| Demo 身份不能直接匹配 Canary | release/deployment identity 拆分和 transition policy | WP8 |
| 约 1 BTC 基线污染 Chaos | 清仓或只用于限定演练，另备干净 Chaos 账户 | §3、§7 |
| 旧 activation 可能释放后续硬故障 | 每个新硬故障推进 hard epoch，风控先于 activation | WP8 |
| 每日两 slot 可事后挑最好样本 | 正式 30 日每日精确一 slot，四时段/流动性分层预注册 | WP3/WP7 |
| buy/exit 不是两个独立统计样本 | 按 probe 聚类并使用 30-cluster Student-t 单侧 UCB | WP7 |
| 外部摘要可自证 clean | 原始 SQLite/monitor/alert/backup bytes 精确回读并语义重建 | WP7 |
| 告警工具形成第二 SQLite 写者 | file-drop inbox，由 trader 唯一验签和写库 | WP6 |
| `PASSIVE busy=0` 仍可能只 checkpoint 少量 frame | 仅 backlog=0 刷新完成时间，持久化 frames/bytes/age 并进 Gate | WP2/WP6 |
| WS/heartbeat 指标存在但未参与 clean 判定 | generation、subscription/recovery、readiness/heartbeat 状态链逐事件闭合并进 Gate | WP2/WP7 |
| 日常组件 restore 被误称为空主机 RTO | 分离 component round-trip 与月度签名 empty-host RTO，后者独立门禁 | WP6/WP7 |
| Chaos receipt 可脱离真实 driver 手填 | 13 个新 inventory 场景固定 `EXTERNAL OPEN`；5 个旧 automated producer 也不得称为生产证据，后续统一纳入不可变 inventory；parser/test actor/test-executor 均不能升级；loader 在读取 receipt 前失败；raw observer/WORM publisher/readback verifier 三身份互异 | WP4/WP5 |
| 同一 barrier 场景二次运行复用证据目录 | systemd `%i` 改为唯一 run-id，scenario 通过不可跟随符号链接的只读 credential 注入；所有 StateDirectory/activation/evidence 路径按 run 隔离 | WP5 |
| OCO `ordId` 被误当父 BUY 关联 | 改用 exact `algoClOrdId` 查询；订单累计成交、基础币手续费和 `lotSz` 共同重算保护数量，所有 OKX 证据强制 Demo header | WP4 |
| kill/恢复源可能在 final cut 前取证 | SIGKILL 后 bounded poll old PID inactive 并延长 restart window；journal readiness 签名完成后才允许 OKX source 采集 | WP5 |
| Canary source key 可为手填 summary 签名 | production signer 只能解析 collector 原始 bytes；12 类 inventory/request/executable/WORM locator hash 全链绑定，API key fingerprint、双对象 backup 和 post-start 状态必须重算；缺真实 IAM/WORM/deployment receipt 时 external readiness 不可绕过 | WP8 |
