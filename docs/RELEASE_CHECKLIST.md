# 生产准入与发布清单

状态：**未准入**。复选框必须由证据负责人签署，不能因为单元测试通过而代签外部条件。

## 工程

- [ ] CI 对目标提交全绿；提交 SHA 与报告链接：
- [ ] 核心状态机分支覆盖率 ≥95%；当前本地基线 96.30%（449 项通过、1 项 TCP-bind
  仅待 Linux CI），CI 证据：
- [ ] 高危静态扫描为零；报告：
- [ ] schema migration 演练通过；证据：
- [ ] 最近一次异地备份恢复演练通过且 RTO <30 分钟；证据：
- [ ] S3 versioned 归档下载、signed manifest、实际解密恢复 round-trip 通过；证据：
- [ ] 备份签名/加密 key ID、历史 keyring 与轮换重叠恢复演练通过；证据：
- [ ] `scripts/fault_injection.py` 在干净目标提交全绿；当前本地故障集合 184 项通过
  （1 项 TCP-bind 仅待 Linux CI），CI artifact 已封入无 `.git` 发布包并绑定
  commit/tree/全源码与测试 manifest SHA，preflight 验证记录：
- [ ] OKX demo contract 通过（独立 OCO ACTIVE、attached 探测结论明确、清理成交）；
  `demo-contract-evidence.json` 与脱敏 `okx-demo-contract-fixture.v1.json`：

## 交易安全

- [ ] 响应丢失不会重复下单：
- [ ] 部分成交正确更新仓位、手续费和保护数量：
- [ ] WS 重连后 REST baseline/对账恢复：
- [ ] 所有非 dust 仓位保护 p99 ≤10 秒：
- [ ] 每个 demo 日锚绑定由 durable system events 生成的 SLO 日报告 SHA-256，且保护
  p99、滑点 p99、未解释对账差异与 ledger 行一致：
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
- [ ] 连续 30 个自然日 demo 无无法解释差异；ledger：
- [ ] API key 仅 Read + Trade、Withdraw 关闭；截图/工单：
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
- [ ] demo 实际滑点没有系统性超过模型：
- [ ] 压力损失在批准资金预算内：
- [ ] 压力 runner attestation 绑定完整 stress evidence SHA，且至少覆盖
  gap≥10%、volume≤25%、volatility≥3x 场景：
- [ ] LLM 策略有固定 prompt/model 版本和独立 shadow A/B 证据（如启用）：

## 运维与安全

- [ ] 外部 heartbeat 能在交易进程死亡且有仓位时 Page：
- [ ] Page/Warning 的接收人与升级路径已演练：
- [ ] `docs/RUNBOOK.md` 已由值班人员走读：
- [ ] 空主机 + 异地备份恢复 RTO <30 分钟：
- [ ] 任意 `clOrdId` 的完整审计链可查询：
- [ ] 非 root、systemd hardening、磁盘/时钟/安全更新已核验：
- [ ] demo、shadow、canary、production key 和状态目录完全隔离：

## Canary 审批

- 目标提交 SHA：
- 账户/子账户：
- 最大总敞口：
- 最大单笔损失：
- 最大日损：
- 允许交易对：
- 开始/结束时间：
- 操作人：
- 风险审批人：
- 回滚责任人：

只有以上四组门槛全部通过，才可将 `admitted=true` 作为生产准入结论。
