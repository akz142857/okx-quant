# Gate A：单机 Demo 验证执行清单

目标：在一台 Linux 主机上，用 Shadow + Active 两个 OKX Demo 账户验证系统；
Chaos 账户可选但推荐。Gate A 通过后只能申请 Gate C 的极小资金、短时、人工监督
Canary，不能宣称生产准入。

## 当前状态

| 项目 | 状态 | 证据/下一步 |
|---|---|---|
| 冻结候选与工作树 clean | `RECHECK REQUIRED` | 提交候选后运行 `git rev-parse HEAD`、`git status --short`；必须为空 |
| 本地全量测试 | `RECHECK REQUIRED` | 在上述候选提交运行 `uv run pytest -q`，保存完整输出（历史基线为 794 passed, 3 skipped） |
| 单机 systemd 静态安全 | `RECHECK REQUIRED` | 在上述候选提交运行 `scripts/linux_deployment_preflight.py --mode static` |
| Linux 实机 preflight | `PENDING` | 在目标 Linux 执行 `--mode live` |
| Shadow/Active 账户与 key | `PENDING` | 两个 Demo 子账户、Withdraw 关闭、IP 白名单 |
| Demo contract v2 | `RE-RUN REQUIRED` | 使用当前冻结候选重新执行并 exact-version 保存 |
| Shadow 72h | `0/72h` | 只读、零交易所写入、WS/SLO/reconciliation ledger |
| Active 7d | `0/7d` | 每日 1 个 5–10 USDT probe、保护/清理/备份/Page |
| 核心 Chaos | `0/6` | SIGTERM、SIGKILL、WS reconnect、REST unknown、external fill、protection cancel |
| 单机 evidence readback | `PENDING` | publisher/verifier 分 key，exact-version 回读 |
| Gate C 双签 Canary | `PENDING` | Gate A 全部通过后，最长 6h、严格额度/日亏/HALT/回滚 |

## 执行顺序

### A1. 目标主机与账户

在一台 Linux 主机上安装冻结候选。至少准备：

- `demo-shadow`：Read-only key；
- `demo-active`：Read + Trade key，仅用于 `validation_probe`；
- 可选 `demo-chaos`：独立 Trade key，用于故障演练。

每个启用 profile 必须有不同 UID、systemd unit、状态/备份目录、凭据、metrics
端口和 network namespace。若分阶段复用账户，必须更换 key/profile，并记录
flat、余额、挂单和 algo 的 pre/post baseline；复用不构成账户隔离证据。

### A2. Linux live preflight

```bash
RELEASE_ROOT=/opt/okx-quant/current
sudo env PYTHONPATH="$RELEASE_ROOT" \
  "$RELEASE_ROOT/.venv/bin/python" \
  "$RELEASE_ROOT/scripts/linux_deployment_preflight.py" \
  --mode live --root "$RELEASE_ROOT" \
  --output /secure-transfer/gate-a-linux-preflight.json
```

必须证明 systemd unit、UID、cgroup、namespace、路径权限和候选 identity 一致。
`preflight_only=true` 只是部署前置证据，不会自动放行交易。

### A3. Demo contract

```bash
"$RELEASE_ROOT/.venv/bin/python" \
  "$RELEASE_ROOT/scripts/demo_contract.py" \
  --config /etc/okx-quant/demo-active.yaml \
  --inst BTC-USDT \
  --confirm I_UNDERSTAND_DEMO_TRADES \
  --output /secure-transfer/gate-a-demo-contract.json \
  --fixture-output /secure-transfer/gate-a-demo-contract-fixture.json \
  --manifest-output /secure-transfer/gate-a-contract-manifest-request.json \
  --release-root "$RELEASE_ROOT"
```

必须满足 `ok=true`、保护生命周期明确、cleanup 无错误、余额/订单/algo 对账通过；
原始文件和 detached signature 使用不可变存储保存，并记录 exact version。

### A4–A5. Shadow 与 Active

先启动 Shadow，连续记录 72 小时：零交易所写入、WS 重连、SLO、reconciliation、
资源和 evidence ledger。Shadow 通过后停止 Shadow writer，再启动 Active，连续 7 日
每天执行一个 5–10 USDT validation probe，并记录保护单、清理、UNKNOWN、备份、Page
和余额回到 baseline 的结果。

### A6. 六项核心故障

逐项执行并单独保存 receipt，故障范围只能是对应 unit/netns/cgroup；禁止 host reboot
或全机 iptables：

1. SIGTERM；
2. SIGKILL；
3. WS down/reconnect；
4. REST 5xx/429/unknown；
5. external fill；
6. protection cancel。

每项必须完成 cleanup、reconciliation、postcondition 和 evidence exact-version 回读。

### A7. Gate C（小资金，不是生产）

仅当 A1–A6 全部通过，且没有 unexplained mismatch，才允许独立 operator/risk
签署最长 6 小时的 Canary policy：单笔/日额度、最大日亏、自动 HALT、人工回滚、
禁止追加资金。Gate C 不会改变 Gate B 的生产扩展状态。

## Gate B：未来扩展记录（当前不执行）

以下项目保留在 [DEMO_SHADOW_REMAINING_TASKS.md](./DEMO_SHADOW_REMAINING_TASKS.md)
和生产计划中，不阻塞 Gate A：

- 第三个 Chaos 账户强制化、第二故障域和多主机切换；
- 18/18 production executor、native live bridge 和 deployment attestation；
- Object Lock COMPLIANCE、跨账号 exact-version、五职责 IAM/WORM；
- 完整 18 项 Chaos matrix；
- 30 个 UTC clean day；
- 生产级 Canary/正式准入 Gate。
