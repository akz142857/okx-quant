# External Evidence Handoff

本文件是冻结候选交给 Linux/云运维团队后的执行清单。它不生成证据，也不把
fixture、人工 JSON 或本机签名升级为生产事实。Gate A 产物必须来自真实 OKX Demo、
单台 Linux/systemd、最小 IAM/STS 和不可变 exact-version 存储；Gate B 才要求
Object Lock COMPLIANCE、第二故障域和独立生产职责。

本轮采用“单台 Linux 主机 + 多个 Demo 子账户”拓扑：Shadow 和 Active 是 Gate A
最低要求，Chaos 子账户是推荐项并在 Gate B 必需。多个账户可以共用一台主机，
但必须使用不同 UID、目录、凭据、端口和 network namespace；Chaos 运行前必须
停止 Active writer。三台主机、第二故障域和跨主机切换属于生产扩展，不是本轮
小资金 Demo 验证前置条件。

冻结候选

```bash
RELEASE_SHA="$(git rev-parse HEAD)"
git status --short                         # 必须无输出
uv run python scripts/recompute_stage_c_evidence.py --output evidence/stage-c-freeze.json
```

`stage-c-freeze.json` 的 `candidate` 必须为 `true`；将其中 revision、source
manifest、inventory、uv.lock 和 systemd unit 摘要作为所有外部证据的绑定输入。

后续命令中的 `CANDIDATE_SHA256` 不是上述 freeze report 的任意字段，也不是
revision 的 SHA-1；它必须替换为正式候选的
`stage_c_chaos_deployment_identity_sha256`（由签名的 deployment identity
manifest 计算并随 external attestation 绑定）。不得自行对 freeze JSON、latest
对象或手写字符串取哈希来代替该值。

## 交接矩阵

| 任务 | 外部执行者必须提供 | 仓内验收入口 | 通过条件 |
|---|---|---|---|
| P0-03 | 干净 Linux CI 日志、systemd-analyze 输出、freeze report | `scripts/verify_systemd_security.py`、`scripts/recompute_stage_c_evidence.py` | Linux 全量 CI 通过，revision/tree/config 一致 |
| P1-01 | 18 个独立 executor artifact、driver/build/IAM/unit 清单 | Stage-C inventory/verifier | 每项独立 `PARSER_READY -> EXECUTOR_SHIPPED`，不得批量升级 |
| P1-02 | 18 项 native raw JSONL、source signer、final loader 回执 | `stage_c_external_bridge`、Stage-C parser | raw bytes 可重算，challenge/consumption/WORM/signatures 全匹配 |
| P1-03 | 4 actor 的 Linux PID/cgroup、collector/signer、cleanup 回执 | `.venv/bin/python scripts/linux_deployment_preflight.py --mode live` | 真实 unit/netns/UID、超时和 cleanup 通过 |
| P1-04 | Gate A：Shadow + Active 两账户的单机 UID/unit/netns/cgroup 回执；Gate B：Chaos/第二故障域 | `.venv/bin/python scripts/linux_deployment_preflight.py --mode live`；Gate B 再用 attestation verifier | Gate A 身份不串线；Gate B 才要求三角色/第二故障域 |
| P1-05 | Gate A：最小 IAM/STS、单机不可变 exact-version；Gate B：COMPLIANCE/跨账号/五职责 | Gate A 用部署/回读 receipts；Gate B 用 `scripts/verify_external_deployment_attestation.py` | 按 Gate 检查对应角色、retention/KMS/readback |
| P1-06 | WP0 v2 contract manifest、OKX contract、单机 evidence version、独立回读签名 | `scripts/verify_demo_contract.py` 及 manifest verifier | candidate/config/account/key/version 全绑定 |
| P2-01 | Shadow 72h ledger、WS/SLO/reconciliation、零写证明 | `scripts/demo_soak_status.py`（逐日/逐 ledger）+ final Gate | 由 epoch/ledger 聚合验证 72h 连续、0 write、0 unexplained mismatch；单次 status 输出不足以证明时长 |
| P2-02 | 7 个完整 probe saga、保护生命周期、14 executions、Page/backup/SLO | `scripts/demo_soak_status.py`（逐日/逐 ledger）+ final Gate | 由 epoch/ledger 聚合验证连续 7 日且 UNKNOWN 三分支均有证据；单次 status 输出不足以证明时长 |
| P2-03 | Gate A：6 张最小 Chaos receipt；Gate B：同一 deployment identity 的 18 张 receipt | `scripts/verify_demo_chaos_coverage.py` | Gate A 仅限 unit/netns/cgroup；Gate B 要求 18/18 在 epoch 开始前完成、identity 精确匹配 |
| P2-04 | 每日 journal/monitor/alert/backup exact-version 原始证据 | daily evidence close / SLO verifier | 30 个完整 UTC clean day，无缺日、变更或硬门槛失败 |
| P2-05 | Gate C：operator/risk 双签小资金 transition policy；Gate B：生产 gate | final production gate | Gate C 在 Gate A 后签署，最长 6 小时、限额/日亏/HALT/回滚；Gate B 才生产准入 |

## 真实 Linux 预检

在目标主机执行（不得在 macOS 上伪造 live 结果）：

```bash
RELEASE_ROOT=/opt/okx-quant/current
sudo env PYTHONPATH="$RELEASE_ROOT" \
  "$RELEASE_ROOT/.venv/bin/python" scripts/linux_deployment_preflight.py \
  --mode live \
  --root "$RELEASE_ROOT" \
  --require-attestation \
  --attestation /secure-transfer/external-deployment-attestation.json \
  --public-key /etc/okx-quant/keys/deployment-verifier-public.pem \
  --expected-candidate-sha256 CANDIDATE_SHA256 \
  --output /secure-transfer/linux-preflight.json
```

`linux-preflight.json` 必须有 `preflight_only=true`；它是部署前置证明，不是
Stage-C capability receipt。任何失败、缺 unit、netns inode 复用、attestation
过期或 candidate hash 不匹配都必须停止后续 soak。

## 外部 attestation 最低约束

Gate A 使用 `linux_deployment_preflight`、Demo contract manifest 和单机 exact-version
receipts；不调用要求完整生产角色集合的 external attestation verifier。Gate B 才必须精确覆盖三账户、三故障域、五个独立
IAM/STS/key 职责，以及 `iam_sts`、`worm_manifest`、`exact_version_readback`、
`second_fault_domain` 四类 evidence。Gate B 的 Object Lock 必须为 `COMPLIANCE`，
retention 覆盖 attestation expiry；所有 Gate 都必须按 signed `VersionId` 获取并
重算 bytes/hash/signature。完成后仅运行验证器：

```bash
uv run python scripts/verify_external_deployment_attestation.py \
  --attestation /secure-transfer/external-deployment-attestation.json \
  --public-key /etc/okx-quant/keys/deployment-verifier-public.pem \
  --expected-candidate-sha256 CANDIDATE_SHA256
```

验证器通过也不等于生产准入；必须继续完成 P2 阶段和双人审批。任何本地 fixture、
手写 receipt、复制私钥、latest object、同机 root 或单一故障域均不合格。

## 回传与状态更新

外部团队回传：原始 bytes、detached signatures、对象 URI + exact VersionId、
STS session、主机/namespace/cgroup 身份、命令版本和 UTC 时间。仓库维护者将其
导入对应 evidence bundle 后重新运行最终 Gate；在此之前保持
`NOT_ADMITTED / EXTERNAL OPEN`，并保持 `implemented_stage_c_scenarios()` 与
`production_instrumented_stage_c_scenarios()` 为空集合。
