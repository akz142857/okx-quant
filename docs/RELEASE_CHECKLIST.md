# 生产准入与发布清单

状态：**未准入**。复选框必须由证据负责人签署，不能因为单元测试通过而代签外部条件。

## 工程

- [ ] CI 对目标提交全绿；提交 SHA 与报告链接：
- [ ] 核心状态机分支覆盖率 ≥95%；目标 Linux CI 对完整、不可漏项 test inventory
  全绿，CI 证据：
- [ ] 高危静态扫描为零；报告：
- [ ] schema migration 演练通过；证据：
- [ ] 最近一次异地备份恢复演练通过且 RTO <30 分钟；证据：
- [ ] S3 versioned 归档下载、signed manifest、实际解密恢复 round-trip 通过；证据：
- [ ] 空主机使用指定 signed receipt 按 archive/manifest exact version GET，
  KMS/Object Lock COMPLIANCE/hash/bytes/schema/account 全部回验并原子安装；证据：
- [ ] backup 身份不写 trader SQLite；签名 restore receipt 由运行时验签并以 trader
  单写者入账，坏签名/陈旧回执演练保持 HALTED：
- [ ] 备份签名/加密 key ID、历史 keyring 与轮换重叠恢复演练通过；证据：
- [ ] `scripts/non_live_validation.py` 在干净目标提交全绿；报告必须绑定完整测试清单
  且保持 `production_admissible=false`，CI artifact/preflight 证据：
- [ ] `scripts/fault_injection.py` 在干净目标提交全绿；当前本地故障集合 191 项通过，
  CI artifact 已封入无 `.git` 发布包并绑定
  commit/tree/全源码与测试 manifest SHA，preflight 验证记录：
- [ ] OKX demo contract 通过（独立 OCO ACTIVE、attached 探测结论明确、清理成交）；
  2026-07-28 交互式行为验证已通过；正式签署仍须提供绑定 commit/tree、配置摘要、
  账户 UID、detached manifest、Object Lock exact version 与独立回读验证的 v2
  evidence，以及脱敏
  `okx-demo-contract-fixture.v1.json`：

## 交易安全

- [ ] 响应丢失不会重复下单：
- [ ] Demo probe 使用 durable saga、stable clOrdId/algoClOrdId、日配额唯一键和
  fencing lease；逐 POST/ACK/保护/cleanup barrier 重启后无重复 BUY：
- [ ] 部分成交正确更新仓位、手续费和保护数量：
- [ ] WS 重连后 REST baseline/对账恢复：
- [ ] 所有独立保护生命周期关联完整率 100%、失败率 0、聚合 p95 ≤3 秒且
  全样本 max ≤10 秒；p99 在独立样本 <300 时仅报告：
- [ ] 每个 demo 日锚绑定 exact SLO v2、policy/epoch/previous hash、Object Lock
  bundle exact version，并覆盖 WS/证据缺口/对账/Page/backup/资源/probe 全部硬指标：
- [ ] 每个 clean day 都有第四个 key 签发的独立 verifier attestation；它对 journal
  snapshot、外部 monitor、provider/human ACK 和 backup receipt 四类原始对象逐一按
  exact version GET 并复核 retention/KMS/bytes/SHA/signature：
- [ ] 每个 Active probe 匹配 epoch 开始前预提交的 UTC slot、交易对、方向和
  spread/volatility bucket；任何越窗或 bucket 不符均为 invalid：
- [ ] `halt-entries` 演练：
- [ ] `resume-entries` 签名双人恢复演练（短效 Ed25519 artifact 绑定 command/account/
  config/expiry 且一次性消费；重启后保持 HALTED、Page challenge 失败保持 HALTED、
  检查通过后才 READY）：
  - operator：
  - risk approver：
  - 证据：
- [ ] 新账户 `init-journal` 演练；缺失/零长日志启动必须 fail closed：
- [ ] receipt/evidence/approval 损坏演练：服务仍以 HALTED safety-only 启动对账/
  保护/退出，且没有策略 worker 或 BUY：
- [ ] `flatten-and-cancel` 签名双人演练（artifact 绑定 action、具体 instruments、
  account/config/command/expiry 且一次性消费）：
- [ ] 同一 `soak_epoch` 连续 30 个完整 UTC clean day；burn-in/invalid 不计数，
  hard breach 打断 streak；ledger：
- [ ] 正式 schedule 至少覆盖连续 30 日、每日精确一个 slot、四个 UTC 时段和至少
  两档 spread/volatility；30 日为 30 个独立 probe、30 个保护生命周期和 60 个
  buy/exit execution，所有 attempt/UNKNOWN/timeout 进入 denominator：
- [ ] Shadow API key 为 Read-only；Active/Chaos 仅 Read + Trade；全部关闭 Withdraw：
- [ ] API key IP 白名单与出口 IP 一致；截图：

## 量化

- [ ] walk-forward 样本外扣动态成本后风险调整收益为正：
- [ ] 组合回测由 `cycle_daily_benchmark` 重算至少 365 个实际日、覆盖率 ≥90%、最大
  缺口 ≤7 天，并在真实 90 日窗口同时跨越获批牛/熊阈值：
- [ ] 参数稳定区域由完整笛卡尔参数 rows 重算，而非 `plateau=true`：
- [ ] 独立研究 policy 在评估前签署 strategy family、完整参数 grid、压力场景和
  exact S3 URI/version/SHA；公钥指纹与证据一致：
- [ ] walk-forward/portfolio 原始数据 URI、对象 SHA、dataset hash、时间范围、交易对、
  bar 与行数 provenance 完整：
- [ ] demo 每笔 realized slippage 的动态模型输出可由冻结 manifest 与原始输入重算；
  buy/exit 按 `probe_id` 聚类，30 个独立 cluster 的 Student-t 单侧 95% 上界 ≤0，
  且不存在缺配对、模型中途变化或删样：
- [ ] 压力损失在批准资金预算内：
- [ ] 压力 runner attestation 绑定完整 stress evidence SHA，且至少覆盖
  gap≥10%、volume≤25%、volatility≥3x 场景：
- [ ] LLM 策略有固定 prompt/model 版本和独立 shadow A/B 证据（如启用）：

## 运维与安全

- [ ] 外部 heartbeat 能在交易进程死亡且有仓位时 Page：
- [ ] Page/Warning 的接收人与升级路径已演练：
- [ ] P0 `provider_received` ≤60 秒；HTTP ingestion 与 provider/human ACK 分层记录，
  dead-man monitor 位于第二故障域：
- [ ] `docs/RUNBOOK.md` 已由值班人员走读：
- [ ] 最近 31 日内有独立签名的空主机 + 异地备份端到端恢复证据，RTO 严格
  <30 分钟；`database_restore_component_only` 不计：
- [ ] local/offsite 已验证可恢复点年龄均 ≤5 分钟，exact version 可独立回读：
- [ ] 四类 external source 公钥已冻结进 soak epoch，彼此及 monitor/risk/observation
  均不同；逐日 exact-version 验证从原始 SQLite 重建 facts 并核对 monitor/alert/
  backup artifact 集合：
- [ ] synthetic challenge/provider/human receipt 由 file-drop inbox 进入，trader 是
  SQLite 唯一写者：
- [ ] 任意 `clOrdId` 的完整审计链可查询：
- [ ] 非 root、systemd hardening、磁盘/时钟/安全更新已核验：
- [ ] Demo Shadow/Active/Chaos 使用独立账户、Unix 身份、release、key、状态目录和
  metrics；Chaos 位于独立故障域，Shadow 不具备 Trade 能力：

## Canary 审批

- 目标提交 SHA：
- release identity/source manifest：
- 账户/子账户：
- account/key fingerprint：
- Demo epoch head / transition artifact：
- policy expiry：
- 最大总敞口：
- 最大订单频率/并发仓位：
- 最大单笔损失：
- 最大日损：
- 最大回撤/滑点：
- 允许交易对：
- 开始/结束时间：
- 自动 halt/flatten 条件：
- 操作人：
- 风险审批人：
- 回滚责任人：
- post-start runtime instance / boot / startup nonce / hard epoch：
- 五项 post-start checks 的预绑定 verifier 指纹与 exact URI/version/SHA/bytes：
- safety kernel 从 `runtime_started_at` 起 60 秒内可观测：
- 5–15 分钟双签 activation artifact：
- `verify_deploy.sh post-activate` 结果（不得在 activation 前要求 READY）：

只有以上四组门槛全部通过，才可将 `admitted=true` 作为生产准入结论。
