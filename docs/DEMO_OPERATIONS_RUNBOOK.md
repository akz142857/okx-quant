# Demo / Shadow 长期验证运行手册

更新时间：2026-07-28

本手册把 `DEMO_SHADOW_VALIDATION_PLAN.md` 转换成可执行流程。仓库中的工具和部署模板
已经具备运行能力，但这不等于已经取得 72 小时、7 日或 30 日证据。任何阶段缺少外部
基础设施、独立签名、完整 UTC 日或真实 OKX Demo 事实时，状态必须保持
**NOT ADMITTED**。

当前执行 profile 是 Gate A：单台 Linux 主机上的 `demo-shadow` + `demo-active` 两个
账户/子账户；`demo-chaos` 可选但推荐。三主机、第二故障域、跨账号职责分离和完整
18 项生产 Chaos 属于 Gate B；Gate A 后的小资金操作还必须经过 Gate C 双人签署、
额度/日亏/HALT/回滚限制。

Gate A 的逐项执行顺序和当前状态见 [`GATE_A_EXECUTION_CHECKLIST.md`](./GATE_A_EXECUTION_CHECKLIST.md)。

本手册后续未显式标注 Gate A 的三主机、第二故障域、完整 18 项或 30 日条款，均是
Gate B 生产扩展路径；Gate A 只执行单机 Shadow/Active、72h/7d、6 项核心故障和
Gate C 双签小资金策略。

## 1. 固定角色和故障域

准备两个不同的 OKX Demo 子账户及 API key（Gate A）；若执行 Gate B，再增加第三个
Chaos 子账户：

| 角色 | 权限 | 允许行为 | 独立边界 |
|---|---|---|---|
| Shadow | Read-only | 行情、账户、订单、WS、对账；永不写交易端点 | account/key/user/group/netns/state/release |
| Active | Read + Trade | 每日精确 1 个 5–10 USDT durable probe | account/key/user/group/netns/state/release |
| Chaos | Read + Trade | 故障、重启、外部干预演练 | 独立 account/key/host 或独立 netns |

所有 key 必须关闭 Withdraw。Active/Chaos 必须有 IP 白名单；Shadow key 不得持有
Trade。三者不得共享 UID、API key 指纹、数据库、备份目录、metrics 端口、Unix
写权限或 network namespace。正式 soak 前，Chaos 账户必须与 Active 完全分离；
约 1 BTC 的历史 Demo 余额只能用于明确绑定 baseline 的 contract/chaos，不能冒充
flat-account 证据。

Active 和 Chaos 还必须连接部署在独立故障域的 account-UID writer lease broker。
在 broker 主机安装 `deploy/systemd/okx-quant-account-lease@.service`、
`deploy/sysusers/okx-quant-account-lease.conf` 和
`deploy/account-lease/account.env.example`，为两个账户使用不同 bearer token。
broker TLS 证书必须被 trader 主机信任；签名私钥和 SQLite lease store 不得出现在
trader 主机。配置中的 URL、公钥、broker ID 和 token env 必须精确匹配。preflight
会先 acquire/release 探测；运行时持续续租，冲突、签名错误或剩余有效期不足 5 秒
都会拒绝开仓并锁存 HALTED；每个 REST 写请求也会在限速等待后、socket write 前重验。
该 broker 是协调租约，不是 OKX 执行的 fencing。没有唯一的 lease-aware 写代理时，
禁止 TTL 到期后自动接管：必须先 STONITH 旧主机、撤销旧 key 或封禁旧 egress，等待
最大在途请求窗口，再以 read-only recovery 完成全账户 reconciliation 后手工放行。

## 2. 离线门禁与发布冻结

在干净的候选提交上运行：

```bash
uv sync --frozen
uv run ruff check .
uv run pytest -q
uv run python scripts/non_live_validation.py \
  --output evidence/non-live-validation.json
uv run python scripts/fault_injection.py \
  --output evidence/fault-injection.json
```

`non-live-validation.json` 必须保持 `production_admissible=false`。它只证明可重复的
离线路径，不能替代 OKX、S3、告警、时间流逝或人工审批。候选提交、tree、source
manifest、`uv.lock`、Python 解释器或运行配置变化后，重新冻结 release；不得把旧
epoch 搬到新身份。

## 3. 发布级 Demo contract

先运行真实 Demo 契约：

```bash
uv run python scripts/demo_contract.py \
  --config config.demo.yaml \
  --inst BTC-USDT \
  --confirm I_UNDERSTAND_DEMO_TRADES \
  --output evidence/demo-contract.json \
  --fixture-output evidence/okx-demo-contract-fixture.v1.json \
  --manifest-output evidence/demo-contract-manifest-request.json
```

只有 `ok=true`、独立 OCO 为 ACTIVE、attached 探测结论明确、cleanup 无残留错误时
才继续。将原始 evidence 和脱敏 fixture 以 KMS + S3 Object Lock COMPLIANCE 上传，
记录各自 exact `VersionId`；风险审批设备再签 detached manifest：

```bash
uv run python scripts/sign_demo_contract_manifest.py \
  --request evidence/demo-contract-manifest-request.json \
  --private-key /risk-device/demo-contract-private.pem \
  --signing-key-id demo-contract-risk-v1 \
  --evidence-uri s3://BUCKET/demo-contract/demo-contract.json \
  --evidence-version-id EXACT_EVIDENCE_VERSION \
  --fixture-uri s3://BUCKET/demo-contract/fixture.json \
  --fixture-version-id EXACT_FIXTURE_VERSION \
  --retain-until 2027-08-01T00:00:00+00:00 \
  --kms-key-id arn:aws:kms:REGION:ACCOUNT:key/KEY_ID \
  --output evidence/demo-contract-manifest.json

uv run python scripts/verify_demo_contract.py \
  --manifest evidence/demo-contract-manifest.json \
  --public-key /etc/okx-quant/keys/demo-contract-public.pem \
  --expected-commit RELEASE_COMMIT \
  --expected-config-sha256 CONFIG_SHA256 \
  --expected-account-uid ACTIVE_DEMO_UID
```

验证器必须使用只读对象存储凭据，并按 manifest 的 exact version GET，同时核对
`aws:kms` 与 signed manifest 中的精确 KMS key identity；禁止用 latest、本地文件或
其他 KMS key 替代独立回读。

## 4. 安装隔离 Demo 服务

从 `deploy/demo/` 复制三份配置和 env 模板，替换所有 `REPLACE_WITH_*`。用以下命令
计算 key 指纹，指纹不得手填：

```bash
uv run python scripts/demo_preflight.py key-fingerprint \
  --config /etc/okx-quant/demo-shadow.yaml
uv run python scripts/demo_preflight.py key-fingerprint \
  --config /etc/okx-quant/demo-active.yaml
uv run python scripts/demo_preflight.py key-fingerprint \
  --config /etc/okx-quant/demo-chaos.yaml
```

安装 `deploy/sysusers/`、`deploy/tmpfiles/`、`deploy/systemd/`、监控规则，以及
`deploy/journald/99-okx-quant-demo.conf`。journald drop-in 是主机级容量策略，必须先按
磁盘预算复核 `SystemMaxUse/SystemKeepFree`；安装后执行
`systemctl restart systemd-journald` 并用 `journalctl --disk-usage` 记录基线。
`deploy/logrotate/okx-quant-demo` 只适用于另行启用的文件 sink，默认 stdout/stderr
由 journald 持久化，不得同时假设两套日志均已采集。

从 `deploy/monitoring/prometheus-agent.yaml.example` 为每个角色生成独立配置，替换
全部 `REPLACE`，将 remote-write CA/client cert/client key 安装到
`/etc/okx-quant/metrics-agent/ROLE/`。client key 必须为对应 monitor 用户 owner、
`0600`，三角色不得共享证书。`okx-quant-demo-metrics-agent@.service` 会进入角色的
network namespace 后抓取 `127.0.0.1`，保留本地 agent WAL，再通过 mTLS
remote_write；禁止把 9208–9210 直接监听到宿主或公网。

在 Linux 主机上按 `deploy/demo/network-namespaces.env.example` 设置网络变量并以
root 运行：

```bash
scripts/setup_demo_namespaces.sh
systemd-sysusers
systemd-tmpfiles --create
systemctl daemon-reload
systemctl enable --now \
  okx-quant-demo-shadow.service \
  okx-quant-demo-active.service \
  okx-quant-demo-watchdog@shadow.service \
  okx-quant-demo-watchdog@active.service \
  okx-quant-demo-metrics-agent@shadow.service \
  okx-quant-demo-metrics-agent@active.service \
  okx-quant-demo-backup@shadow.timer \
  okx-quant-demo-backup@active.timer \
  okx-quant-demo-offsite-restore@shadow.timer \
  okx-quant-demo-offsite-restore@active.timer \
  okx-quant-demo-alert-challenge@shadow.timer \
  okx-quant-demo-alert-challenge@active.timer \
  okx-quant-demo-evidence-close@shadow.timer \
  okx-quant-demo-evidence-close@active.timer
```

启用前和每次监控规则变更后必须执行：

```bash
uv run python scripts/validate_monitoring_config.py
promtool check rules deploy/monitoring/prometheus-rules.yaml
amtool check-config deploy/monitoring/alertmanager.yaml.example
```

随后从 remote-write 接收端确认三个独立 `up` 序列、external labels 和 agent WAL
重启续传；只看到 trader 本机 `/metrics` 不算外部监控已经闭环。

每次启动时 `demo_preflight.py issue/verify` 都会重新验证角色、账户/key 指纹、权限
模式、路径、systemd unit、netns、metrics 端口、磁盘/inode、时钟和 peer 隔离。
receipt 位于角色专属目录，目录必须是 `root:<role-data-group> 0750`，文件必须是
`root:<role-data-group> 0640`：目标 trader 可读但不可改。`main.py` 在创建 OKX
client 前还会独立重算 release/config/account/unit 身份，并核对实际 Unix UID、
systemd service cgroup、当前 netns inode 及完整 live argv
（strategy/bar/instruments/interval）。因此直接运行 `main.py`、复制 receipt 到其它
角色、修改参数或离开受控 unit/netns 都会在产生正式 soak facts 前拒绝启动。

## 5. Soak epoch 与阶段顺序

正式计时前在干净 release checkout 生成 epoch 请求：

```bash
uv run python scripts/generate_probe_schedule.py \
  --start-day 2026-08-01 \
  --days 30 \
  --inst BTC-USDT \
  --output /secure-transfer/probe-schedule.json

uv run python scripts/create_soak_epoch_request.py \
  --config /etc/okx-quant/demo-active.yaml \
  --release-root /opt/okx-quant/demo-active/current \
  --release-evidence /opt/okx-quant/demo-active/current/non-live-validation.json \
  --soak-epoch-id demo-RELEASE-001 \
  --started-at 2026-08-01T00:00:00+00:00 \
  --strategy validation_probe \
  --bar 1H \
  --instrument BTC-USDT \
  --interval-seconds 60 \
  --probe-schedule /secure-transfer/probe-schedule.json \
  --host-image-sha256 HOST_IMAGE_SHA256 \
  --launch-sha256 LAUNCH_SHA256 \
  --monitor-public-key /etc/okx-quant/keys/demo-monitor-public.pem \
  --risk-public-key /etc/okx-quant/keys/epoch-risk-public.pem \
  --observation-public-key /etc/okx-quant/keys/demo-observation-public.pem \
  --journal-snapshot-public-key /etc/okx-quant/keys/journal-snapshot-public.pem \
  --external-monitor-public-key /etc/okx-quant/keys/external-monitor-public.pem \
  --alert-receipts-public-key /etc/okx-quant/keys/alert-receipt-public.pem \
  --backup-receipts-public-key /etc/okx-quant/keys/backup-receipt-public.pem \
  --canary-producer-inventory /secure-transfer/canary-producer-inventory.json \
  --stage-c-chaos-deployment-identity \
    /secure-transfer/stage-c-chaos-deployment-identity.json \
  --operator operator@example \
  --risk-approver risk@example \
  --output /secure-transfer/soak-epoch-request.json
```

`REVISION`、`non-live-validation.json`、当前源码 manifest、`uv.lock` 和当前
Python interpreter 必须共同形成同一个 exact release identity。monitor、risk、
observation 与 journal/monitor/alert/backup 四类 external source 共七个角色的
指纹从规范化公钥 DER 派生，七者必须互不相同并冻结进 epoch；复制同一把私钥到
不同路径仍会被拒绝。

`stage-c-chaos-deployment-identity.json` 必须在 epoch 创建前冻结 exact-release
与 instrumented 两类 account/config/unit/artifact、host image、netns/cgroup policy、
observer/source key、safety behavior 和 build provenance；最终 18 项 matrix 回执必须
逐项匹配该身份且全部早于 epoch `started_at`。

独立 monitor 与 risk approver 分别核对后双签：

```bash
uv run python scripts/sign_soak_epoch.py \
  --request /secure-transfer/soak-epoch-request.json \
  --monitor-private-key /monitor-device/epoch-private.pem \
  --risk-private-key /risk-device/epoch-private.pem \
  --output /etc/okx-quant/admission/demo-soak-epoch.json
```

签署后，把 artifact 中的 exact `soak_epoch_id` 同步写入对应
`demo_validation.soak_epoch_id` 和独立监控主机的
`OKX_QUANT_SOAK_EPOCH_ID`，然后重新生成 preflight receipt。trader 的 health/ready
会回报该值，外部监控从响应中读取并逐端点比较；任一侧缺失、回显旧 epoch 或与配置
不一致都会 fail closed。不能只在监控命令行回显 expected 值。

必须依次运行：

1. Shadow 至少连续 72 小时，只读 key、零写端点；
2. Active burn-in 至少连续 7 日，累计验证 probe、Page、备份和资源曲线；
3. release freeze 后，在隔离 Chaos 环境完成最终黑盒 fault matrix；
4. 为冻结后的 exact release 创建新的 `phase=soak` epoch；
5. 同一 epoch 完成连续 30 个完整 UTC clean day。

Shadow、burn-in、chaos 和首尾不足 24 小时的窗口都不能计入 30 日 clean streak。
ledger 只接受 UTC 日起点不早于 `epoch.started_at` 的完整日；若 epoch 在某日中途
启动，该日不能写入或计数，最早从下一 UTC 日开始。
hard breach 必须追加 `invalid`，不能删除、跳日或回填。

## 6. 每日自动日结

`okx-quant-demo-evidence-close@ROLE.timer` 在第二天关闭前一个完整 UTC 日。它会：

1. 在同一个显式只读事务中导出 allowlist raw facts，并由该 frozen facts 重算 SLO v2；
2. 汇总 WS、evidence gap、reconciliation、alert/provider/human ACK、local/offsite
   RPO、clock、resource、probe、protection 和 slippage；
3. 将 raw facts 和报告作为两个独立 component 按 exact version 写入 KMS +
   Object Lock COMPLIANCE；
4. 签名 bundle manifest 和 observation anchor，并 exact-version 回读；
5. 将 `clean|invalid|burn-in` 追加到 hash-chain ledger；
6. 在 ledger 已写但本地 rename 中断时执行确定性 crash recovery。

日结进程的签名和 readback 不是独立复验。位于第二故障域的 verifier 必须使用自己的
只读 S3/IAM 和第四个 Ed25519 key，对每个 daily bundle 执行 exact-version GET，
从 raw facts 重算 report，并产生签名 attestation：

四类原始输入先分别由各自身份生成不可覆盖的日聚合 artifact；每个 `--artifact`
都是该来源的原始 JSON fact/receipt，不能为空：

```bash
uv run python scripts/sign_external_daily_source.py \
  --day 2026-07-28 \
  --source external_monitor \
  --artifact /secure-transfer/raw/monitor-observations.json \
  --private-key /monitor-device/external-monitor-private.pem \
  --signing-key-id external-monitor-v1 \
  --output /secure-transfer/2026-07-28-external-monitor.json
```

`journal_snapshot` 不能使用摘要 JSON 代替数据库。先对在线数据库创建 SQLite
checkpoint snapshot，上传该 `.db` 的 Object Lock exact version，再签 locator：

```bash
uv run python scripts/sign_journal_snapshot_locator.py \
  --snapshot /secure-transfer/2026-07-28/trading.db \
  --day 2026-07-28 \
  --account-id ACTIVE_DEMO_UID \
  --object-uri s3://EVIDENCE/raw/2026-07-28/trading.db \
  --version-id EXACT_SQLITE_VERSION \
  --private-key /journal-device/journal-private.pem \
  --output /secure-transfer/raw/journal-snapshot-locator.json
```

然后以该 locator 作为 `journal_snapshot` 的唯一 `--artifact`。对
`alert_receipts`、`backup_receipts` 使用各自身份重复聚合；provider receipt、
human ACK 和 escalation 还必须分别使用三个互异公钥。四个签名聚合物按 Object
Lock exact version 发布，不得把四类事实合并后用同一 key 签名。

```bash
uv run python scripts/immutable_evidence_bundle.py verify \
  --manifest /secure-transfer/2026-07-28/bundle-manifest.json \
  --manifest-uri s3://EVIDENCE/epoch/day/bundle/manifest.json \
  --manifest-version-id EXACT_VERSION_ID \
  --identity /secure-transfer/2026-07-28/identity.json \
  --public-key /etc/okx-quant/keys/demo-observation-public.pem \
  --minimum-retain-until 2027-08-01T00:00:00Z \
  --kms-key-id EVIDENCE_KMS_KEY_ID \
  --verifier-private-key /verifier-device/evidence-verifier-private.pem \
  --verifier-key-id evidence-verifier-v1 \
  --external-verification-summary /verifier-device/2026-07-28-external-summary.json \
  --external-signing-public-key journal_snapshot=/verifier-device/keys/journal-public.pem \
  --external-signing-public-key external_monitor=/verifier-device/keys/external-monitor-public.pem \
  --external-signing-public-key alert_receipts=/verifier-device/keys/alert-receipt-public.pem \
  --external-signing-public-key backup_receipts=/verifier-device/keys/backup-receipt-public.pem \
  --alert-receipt-public-key provider=/verifier-device/keys/provider-receipt-public.pem \
  --alert-receipt-public-key human-ack=/verifier-device/keys/human-ack-public.pem \
  --alert-receipt-public-key escalation=/verifier-device/keys/escalation-public.pem \
  --receipt-output /secure-transfer/daily-verifier-attestations/2026-07-28.json
```

publisher 与 verifier 的规范 Ed25519 公钥指纹相同会被拒绝。生产 Gate 同时要求
`--bundle-signing-public-key`、`--independent-verifier-public-key` 和
`--independent-verifier-attestations-dir`，并逐日核对 manifest URI、version、
SHA-256、identity、report hash 和重算签名；旁路生成但未交给 Gate 的 receipt 不算
准入证据。`external-verification-summary` 必须逐类绑定 journal snapshot、第二故障域
monitor observations、provider/human ACK receipts 和 offsite restore receipts 的
S3 URI、exact version、SHA-256、byte length、签名 key fingerprint、artifact count
与验签结论。`verify` 会对四类对象逐一执行带 version ID 的 HEAD/GET，复核
COMPLIANCE retention、KMS、bytes 和 SHA-256，再使用四个显式公钥验证日聚合
artifact 的 Ed25519 签名、日期、source 和 artifact count，之后才签署 attestation；
还会从原始 SQLite 重建 frozen facts、验证 monitor 全日 ≤5 分钟覆盖，并将
alert/backup receipt digest 集合与 journal facts 精确比对。任一类为空、语义不符、
未验签、来源公钥不等于 epoch 预注册值或 exact-version 读取失败时 verifier 和 Gate
都拒绝。

异地恢复服务不得直接打开 trader SQLite。它以隔离 backup 用户原子发布
group-readable 的签名回执；交易运行时只读回执、验签并由自身记录
`backup_slo_sample`，从而维持 trader 单写者。如果回执缺失、损坏、签名错误或超过
RPO，entries 保持 HALTED 并 Page。

检查状态：

```bash
uv run python scripts/demo_soak_status.py \
  --ledger /var/lib/okx-quant-evidence/demo-active/soak-ledger-v2.json \
  --epoch-payload /etc/okx-quant/admission/demo-soak-epoch.json \
  --observation-public-key /etc/okx-quant/keys/demo-observation-public.pem \
  --max-slippage 0.005
```

日结退出码 2 表示该日被可靠地记录为 invalid，不是可以重跑覆盖的临时错误。只有基础
设施失败且 ledger 尚未提交时才允许在修复后重试同一天。

当前 ledger v2 对缺日采用 fail-closed：日期空洞会立即打断 clean streak，但不能由
trader 或日结进程自行伪造一个历史 `invalid` 行。安全的缺日 tombstone 必须由第二
故障域的 deadline monitor 在日结截止后签发，绑定 epoch、缺失 UTC day、previous
ledger head、截止时间和“该日没有 exact-version daily bundle”的独立对象存储查询
receipt；随后由下一版 ledger schema 追加该签名 tombstone。该 schema 上线前，缺日
只能保持为空洞并令 Gate 为 0 天，禁止人工回填、临时生成 report 或修改 ledger。

正式准入 request/风险批准使用 v2；deployment receipt 使用 v3。三者同时绑定
`demo_ledger_version=2`、`slo_schema=okx-quant.demo-slo/v2` 和当前
`slo_policy_hash`，v3 receipt 还绑定月度 empty-host restore SHA-256 与完整 Stage-C
coverage SHA-256。升级前生成的 v1/v2 receipt 必须被 `activate_release.py` 拒绝并
重新走 Gate；不得为了复用旧 receipt 删除字段或降低版本号。

## 7. 告警演练

Alertmanager/接收器配置见 `deploy/monitoring/`。逐项制造 P0/P1，并导入 provider 与
human ACK 签名 receipt：

```bash
uv run python scripts/import_alert_receipt.py \
  provider \
  --inbox /var/lib/okx-quant/demo-active/operator-inbox \
  --expected-account-id ACTIVE_DEMO_UID \
  --artifact /secure-transfer/provider-or-human-receipt.json
```

该命令只原子写入 file-drop request，不打开 SQLite；运行中的 trader 按请求 kind
使用配置冻结的 `alert_provider_receipt_public_key`、
`alert_human_ack_public_key` 或 `alert_escalation_public_key` 验签后作为唯一数据库
写者入账；三个身份必须互异。每日 timer 同样只向 inbox 投递 synthetic challenge。

必须证明稳定 event ID、幂等投递、持久重试/DLQ、P0 provider received ≤60 秒、
P1 ≤300 秒，以及无人响应时独立升级。Webhook HTTP 2xx 只算 ingestion，不能冒充
provider received 或 human ACK。trader、watchdog、外部 monitor 任一死亡时，另外
两个仍须能 Page。

独立 monitor 必须安装在第二故障域，启用
`deploy/external-monitor/okx-quant-demo-external-monitor@.service`，并配置该目录
对应 role 的 env。除 trader 的 `/healthz`、`/readyz` 外，它强制读取五个 HTTPS
dead-man endpoint：`host`、`service`、`provider`、`evidence-close`、`backup`。
缺任意 endpoint、signal 过期或 identity 串线都会同时向两个不同 origin 的 Page
路由告警。每个 endpoint 返回的 JSON 必须精确包含：

```json
{
  "ok": true,
  "signal": "backup",
  "observed_at": 1785219200.0,
  "deadman_id": "stable-source-event-id",
  "target": "demo-active",
  "release_identity": "40_HEX_COMMIT",
  "config_identity": "64_HEX_CONFIG_SHA256",
  "account_uid": "ACTIVE_DEMO_UID",
  "deployment_unit": "okx-quant-demo-active.service",
  "soak_epoch_id": "CURRENT_EPOCH_ID"
}
```

允许的最大计龄固定为 host 120 秒、service 60 秒、provider 900 秒、
evidence-close 90,000 秒、backup 300 秒；不得由运行时配置静默放宽。独立 signal
gateway 应从 host exporter、systemd 状态、provider challenge、日结 timer receipt
和 exact-version restore receipt 产生这些事实，不能回显 monitor 的期望参数。

在第二故障域安装 sysusers、service/timer/env/key 后，为实际观察角色启用 timer：

```bash
systemd-sysusers deploy/sysusers/okx-quant-external-monitor.conf
systemctl daemon-reload
systemctl enable --now \
  okx-quant-demo-external-monitor@demo-shadow.timer \
  okx-quant-demo-external-monitor@demo-active.timer
```

检查 `systemctl list-timers`、两条独立 Page route 和
`/var/lib/okx-quant-external-monitor/TARGET/incidents.json`。同一持续事故的重试必须
复用 event ID；两路都确认 ingestion 后停止重复发送；出现健康观测清除 active
incident，之后同类故障复发必须生成新的 event ID。该本地状态只能用于告警去重，
不能替代签名 observation 或 provider receipt。

## 8. 备份与空主机恢复

本地一致性快照每 60 秒；异地 exact-version restore check 每 2 分钟。SLO 按最近一
个完整、签名且实际恢复成功的 recovery point 计龄，local/offsite 均不得超过 300
秒。S3 bucket 必须启用 Versioning、Object Lock COMPLIANCE、KMS、跨账号只读验证
和 deny `DeleteObjectVersion`。

每月至少在无旧数据库、无 trader 进程的干净 Linux 主机演练一次。先从 receipt 的
WORM publication metadata 按 exact version 下载 signed receipt，再运行：

```bash
uv run python scripts/offsite_restore_check.py \
  --backup-env /etc/okx-quant/demo-active-restore.env \
  --local-backup-dir /var/lib/okx-quant-backup/demo-active \
  --receipt /secure-transfer/trading-TIMESTAMP.db.enc.offsite-receipt.json \
  --manifest-public-key /etc/okx-quant/keys/backup-manifest-public.pem \
  --evidence-private-key /etc/okx-quant/keys/active-restore-private.pem \
  --evidence-public-key /etc/okx-quant/keys/active-restore-public.pem \
  --evidence-key-id demo-active-restore-v1 \
  --minimum-remaining-retention-days 30 \
  --materialize-dir /var/lib/okx-quant-restore/exact-recovery \
  --output /var/lib/okx-quant-restore/offsite-roundtrip.json

uv run python scripts/cold_restore.py \
  /var/lib/okx-quant-restore/exact-recovery/trading-TIMESTAMP.db.enc \
  --target /var/lib/okx-quant/demo-active/trading.db \
  --expected-account-id ACTIVE_DEMO_UID \
  --expected-schema-version 11 \
  --manifest-public-key /etc/okx-quant/keys/backup-manifest-public.pem \
  --expected-signing-key-id BACKUP_SIGNING_KEY_ID \
  --expected-encryption-key-id BACKUP_ENCRYPTION_KEY_ID \
  --actor disaster-recovery@example \
  --service-unit okx-quant-demo-active.service \
  --owner-user okxquant-demo-active \
  --owner-group okxquant-data-active \
  --output /var/lib/okx-quant-restore/cold-restore-receipt.json
```

`offsite_restore_check.py` 的 `roundtrip_started_at/completed_at` 只衡量数据库 component
的 exact-version 下载、解密和完整性检查；日报将其记录为
`component_restore_*`，它不能满足 30 分钟整机 RTO。完整演练必须另建严格 request，
覆盖空主机确认、依赖/配置安装、exact version GET、数据库/account/schema/integrity、
MAINTENANCE 锁存、只读 reconciliation、entries 仍关闭、host image 和 component
evidence SHA。独立 DR verifier 复核后签名：

```bash
uv run python scripts/sign_empty_host_restore.py \
  --request /secure-transfer/empty-host-request.json \
  --private-key /dr-verifier/empty-host-private.pem \
  --public-key /dr-verifier/empty-host-public.pem \
  --evidence-key-id empty-host-dr-v1 \
  --minimum-retain-until 2027-09-01T00:00:00+00:00 \
  --kms-key-id REPLACE_EVIDENCE_KMS_KEY \
  --output /secure-transfer/empty-host-restore.json
```

request 的 `measurement_scope` 必须精确为 `empty_host_end_to_end`，端到端
`elapsed_seconds` 必须与起止时间一致且严格小于 1800 秒。生产/Canary Gate 只接受
最近 31 日、绑定当前 Demo soak account/release/config/unit/epoch 的该签名 artifact，并将
artifact SHA-256 写入风险批准；普通 component restore、旧证据或手填 operational
check 均不能替代。独立 DR signer 会在签名前对 archive 与 manifest 的 URI、
version ID、hash、bytes、Object Lock retention 和 KMS 实际执行 exact GET；request
中的 `exact_version_get_verified=true` 不能自证。把 artifact 安装为
`/etc/okx-quant/admission/empty-host-restore.json`，公钥安装为
`/etc/okx-quant/keys/empty-host-restore-public.pem`。

计时从空机开始，到依赖/配置安装、exact GET、解密、schema/account/integrity 检查、
原子安装、MAINTENANCE 锁存和只读 OKX reconciliation 完成为止，必须小于 30 分钟。
恢复后禁止直接 READY；必须人工裁决差异并走签名 resume。

## 9. Chaos matrix

`scripts/demo_chaos_matrix.py` 只允许在 Chaos 身份执行，并要求精确确认词。最终 freeze
后至少覆盖 WS public/private/business、SIGTERM、SIGKILL、主机重启、只读数据库、
SQLITE_FULL、磁盘/inode、POST/ACK loss、partial fill、外部撤保护和 REST/WS 差异。
每个结果必须绑定 exact release identity 并写入不可变 bundle。

仓库中的稳定目录由
`okx_quant.ops.demo_chaos_evidence.DRILL_SCENARIOS` 定义，Stage-C 必须精确覆盖全部
18 个场景。15 个黑盒场景必须使用 `exact_release_black_box`；三个 POST/ACK/fill
内部 barrier 必须使用独立的 `instrumented_test_only` artifact hash 且显式声明
test hook。`scripts/demo_chaos_matrix.py` 会拒绝执行 test-only 场景，避免将测试构建
冒充正式候选。

五个可安全自动控制的场景使用 `automated_control` adapter。其余十个需要交易所外部
状态、真实部分成交、保护单或灾备控制器的场景使用
`independent_raw_observation` adapter：缺少 32-hex challenge、独立 observer 公钥
或签名 observation 时 runner 在读取配置前直接阻断。observation 必须精确绑定当前
release/config/account/unit/epoch、完整状态迁移、Page/reconciliation/postcondition，
并引用机器采集原始记录的 S3 URI、exact version、SHA-256 和 bytes；不能把本机手填
receipt 当作原始观测。第二故障域 verifier 会额外 exact GET 该 raw source。

但 locator、签名 observation 和 exact GET 只证明“某些 bytes 存在”，不能证明这些
bytes 的交易语义。当前生产能力清单如下；`EXTERNAL OPEN` 是硬门禁状态，不是允许运维
手工补证的待办标签：

| 场景 | 状态 | 解除门禁所缺能力 |
| --- | --- | --- |
| `ws-public`, `ws-private`, `ws-business`, `restart-sigterm`, `restart-sigkill` | `IMPLEMENTED` | 自动 exact-release producer 已存在 |
| `ws-partial-fill-recovery`, `clordid-conflict`, `rest-5xx-429-unknown`, `oco-active-process-death`, `restart-while-ws-down`, `backup-db-corruption` | `PARSER_READY / EXTERNAL OPEN` | challenge-bound 真实故障 executor、全部 source-role unit/IAM/signer 与 WORM 运行证据 |
| `external-pending-buy`, `external-fill`, `external-protection-cancel`, `frozen-balance` | challenge/consumption/workload-bound Demo actor、durable pre-intent、独立 raw collector 与 cleanup unit；`EXTERNAL OPEN` | 独立 source signer、真实 Linux orchestration/DynamoDB/IAM、final live bridge、同快照 WORM/readback/deployment attestation；完成前仓内 actor 不得作为生产 receipt 来源 |
| `barrier-buy-intent-before-post`, `barrier-post-before-ack`, `barrier-fill-before-projection` | repository test-executor；构建产物可由专用 Python 解释器执行 self-check，但尚无 pipeline/TLS activation CLI；`EXTERNAL OPEN` | 由签名 challenge 激活完整 trader 的部署入口、native recovery→core raw-event adapter、独立 source signer、真实 systemd kill/restart、恢复最终快照与 WORM attestation |

因此当前 18 项 schema/coverage contract 已实现，但生产 Stage-C 只有 5 项证据生产能力
已实现，另外 13 项会由 `load_verified_stage_c_receipts` fail closed。即使 receipt
字段完整、observer 签名有效、raw S3 locator 可读、WORM readback 也不能解除
`EXTERNAL OPEN`；必须提交相应 production executor、逐场景语义 verifier 和部署/
验证制品后改变能力清单。
仓内的 allowlist systemd/procfs/SQLite/HTTPS/proxy collector、受控故障原语和
DynamoDB 条件消费 challenge 可供这些场景实现复用，但它们只证明采集、身份和一次性
消费协议，不能自行证明 partial fill、UNKNOWN 或三个 barrier 的业务状态迁移。

raw 场景使用三层能力状态：注册固定 parser 只能到 `PARSER_READY`；仓库存在真实
scenario executor 后只能到 `EXECUTOR_SHIPPED`；`DEPLOYMENT_ATTESTED` 不能写进
配置或由调用方传入，只能由 production loader 在当前运行中复验 signed registrar
challenge、短效 capability、systemd/proc/STS workload、完整 source-role 签名和
冻结 raw bytes 后得出。部署前按以下固定目录构建 trust config：

`EXECUTOR_SHIPPED` 不是“目录中存在若干文件”的别名。实现清单会复算实际源码与制品
hash，并要求每个 source role 的 collector/systemd/IAM 绑定及逐场景语义 verifier；
当前语义 verifier registry 为空，所以 13 项即使放入格式正确的假 driver、假 unit、
假 IAM 或虚构 test ID 也会 fail closed。

```text
/etc/okx-quant/keys/stage-c/global/parser-signer-public.pem
/etc/okx-quant/keys/stage-c/<scenario>/registrar-public.pem
/etc/okx-quant/keys/stage-c/<scenario>/capability-authority-public.pem
/etc/okx-quant/keys/stage-c/<scenario>/sources/<role-except-parser_signer>-public.pem
```

```bash
uv run python scripts/build_stage_c_trust_manifest.py \
  --raw-events-dir /etc/okx-quant/admission/stage-c/raw-events \
  --key-root /etc/okx-quant/keys/stage-c \
  --output /etc/okx-quant/admission/stage-c/trust-manifest.json
```

builder 精确枚举 13 个场景和每个 parser 要求的角色，计算 driver contract、raw
SHA-256/bytes 与公钥指纹，拒绝覆盖已有 manifest、符号链接、非规范路径、可由
group/world 写的输入以及未授权的跨场景/角色 key 复用。唯一允许复用的是所有场景
共同绑定的 `parser_signer`，它必须精确等于 Gate 的 global raw-observer key；
registrar、capability authority 和其余 native source keys 必须全局唯一，并与
publisher/raw-observer/readback verifier 分钥。manifest 的
`TRUST_CONFIGURED` 仅表示冻结信任配置，绝不等于 deployment attestation。

每个 WORM bundle 上传后，必须在第二故障域对 manifest 和 `drill-result` 分别按
`version_id` 执行 exact GET，并用不同于 publisher 的 verifier key 签署 readback：

```bash
uv run python scripts/verify_demo_chaos_coverage.py \
  --scenario ws-public \
  --manifest /secure-transfer/stage-c/manifests/ws-public.json \
  --manifest-uri s3://REPLACE/stage-c/BUNDLE/manifest.json \
  --manifest-version-id REPLACE_EXACT_VERSION \
  --bundle-signing-public-key /etc/okx-quant/keys/demo-monitor-public.pem \
  --independent-verifier-private-key /secure-verifier/evidence-private.pem \
  --independent-verifier-key-id evidence-verifier-v1 \
  --minimum-retain-until 2027-07-28T00:00:00+00:00 \
  --kms-key-id REPLACE_KMS_KEY \
  --output /secure-transfer/stage-c/independent-readbacks/ws-public.json
```

生产 Gate 分别读取按 `<scenario>.json` 命名的 result、signed manifest、bundle
receipt 和 independent readback 目录，并强制所有 drill 的开始时间晚于
`--stage-c-release-frozen-at`。它还要求
`--stage-c-raw-observer-public-key` 及 `--stage-c-trust-manifest`；raw observer、
WORM bundle publisher 和
readback verifier 的规范 Ed25519 指纹必须三者互异。本地 JSON、仅有本地 bundle
receipt，或复用 observer/verifier key 均不能通过。

验收条件是：无重复 BUY；非 dust 仓位始终有 ACTIVE 保护或进入 emergency；startup
reconciliation ≤60 秒；数据库 integrity `ok`；任何 UNKNOWN/unresolved 保持
HALTED/MANUAL_REVIEW。影响 runtime/config/schema 的修复会使旧 matrix 失效。

## 10. Demo → Canary

Canary 的唯一语义是 `environment=production` 且 `deployment_tier=canary`；没有第三种
runtime environment。先用 30 个 clean day 的 epoch/ledger 和目标真实账户身份生成
target identity：

```bash
uv run python scripts/canary_artifact.py target-identity \
  --soak-epoch /etc/okx-quant/admission/demo-soak-epoch.json \
  --epoch-monitor-public-key /etc/okx-quant/keys/epoch-monitor-public.pem \
  --epoch-risk-public-key /etc/okx-quant/keys/epoch-risk-public.pem \
  --target-config /etc/okx-quant/config.yaml \
  --target-env /etc/okx-quant/production.env \
  --runtime-identity /secure-transfer/canary-runtime-identity.json \
  --output /secure-transfer/canary-target-identity.json
```

先把
[`deploy/canary-producers/inventory.json.example`](../deploy/canary-producers/inventory.json.example)
的 12 类 producer 全部替换为真实公钥、Unix collector/signer、两套 systemd unit、
IAM principal 和隔离路径，并在创建 soak epoch 时用
`--canary-producer-inventory` 预注册。collector 对 raw path 有写权；signer 只有读权，
且 transition 只接受与 epoch inventory 精确一致的 12 把 source key。

七个 pre-start source artifact 必须携带固定类型的 raw response/snapshot/config
bytes；validator 从嵌入 bytes 重算 facts。生产 CLI 不接受任意本地 JSON，也不把
可自设的 environment variable 当成 systemd/IAM 身份证明。
测试通过纯函数构造 envelope；生产 CLI 不提供环境变量或隐藏开关。

当前 12 类 production producer 的仓内 collector/signer、systemd、独立 WORM
readback/deployment verifier 和 capability 聚合器已经实现，但 12 路真实运行证据
仍全部是 **EXTERNAL OPEN**。在独立主机尚未提供可验证的 cgroup/systemd invocation、
实际 OKX credential fingerprint、外部 IAM/STS identity receipt 与冻结
Object Lock exact-version readback 前，Canary production promotion 必须保持
blocked。详见
[`deploy/canary-producers/README.md`](../deploy/canary-producers/README.md)。

WORM verifier 不接受预制 `Authorization` 字符串：它从隔离的 systemd credential
读取 AWS access/secret/session，按冻结 region、canonical object key 和唯一
`versionId` 动态生成 S3 SigV4；reader access-key fingerprint、S3 origin、KMS ARN
必须与 transition inventory 精确一致。post-start position/algo/order 还会对
REST/WS/journal 的数量、方向、状态与事件水位作本地重算，超过 30 秒或三方冲突即失败。

此链路必须分两阶段执行，不能把 capability unit 当作上传器：先在全新的 epoch
目录运行 12 路 collector/signer，固化 IAM/STS receipt，将每个新生成的
`source.json` 上传到预注册 Object Lock bucket 并取得真实 `versionId`；再冻结
capability manifest 与每路 WORM 环境文件，最后启动 capability unit，由 systemd
依赖等待 12 次 exact-version readback 和 deployment verifier。若跳过第一阶段直接
启动，缺 version、receipt 或 bytes 不匹配必须 fail closed。

七类检查必须恰好是 `account_uid_verified`、`api_key_read_trade_only`、
`api_key_withdraw_disabled`、`ip_allowlist_verified`、
`journal_identity_verified`、`limits_match_policy` 和
`release_identity_verified`。签名 observation 必须在 transition 使用时不超过 15
分钟；缺项、过期、raw bytes/facts 重算不一致、hash/签名错误、source key 重用、
inventory 不匹配或身份串线都会 fail closed。limits 必须精确等于该 config bytes
导出的冻结值，policy 不再允许“只要比配置宽松”。

随后生成 transition request，再由 operator/risk 双签：

```bash
uv run python scripts/canary_artifact.py request-transition \
  --soak-epoch /etc/okx-quant/admission/demo-soak-epoch.json \
  --epoch-monitor-public-key /etc/okx-quant/keys/epoch-monitor-public.pem \
  --epoch-risk-public-key /etc/okx-quant/keys/epoch-risk-public.pem \
  --ledger /var/lib/okx-quant-evidence/demo-active/soak-ledger-v2.json \
  --observation-public-key /etc/okx-quant/keys/demo-observation-public.pem \
  --pre-start-check account_uid_verified=/secure-transfer/pre-start-account.json \
  --pre-start-check api_key_read_trade_only=/secure-transfer/pre-start-permissions.json \
  --pre-start-check api_key_withdraw_disabled=/secure-transfer/pre-start-withdraw.json \
  --pre-start-check ip_allowlist_verified=/secure-transfer/pre-start-ip.json \
  --pre-start-check journal_identity_verified=/secure-transfer/pre-start-journal.json \
  --pre-start-check limits_match_policy=/secure-transfer/pre-start-limits.json \
  --pre-start-check release_identity_verified=/secure-transfer/pre-start-release.json \
  --pre-start-source-public-key account_uid_verified=/etc/okx-quant/keys/account-pre-start-public.pem \
  --pre-start-source-public-key api_key_read_trade_only=/etc/okx-quant/keys/permissions-pre-start-public.pem \
  --pre-start-source-public-key api_key_withdraw_disabled=/etc/okx-quant/keys/withdraw-pre-start-public.pem \
  --pre-start-source-public-key ip_allowlist_verified=/etc/okx-quant/keys/ip-pre-start-public.pem \
  --pre-start-source-public-key journal_identity_verified=/etc/okx-quant/keys/journal-pre-start-public.pem \
  --pre-start-source-public-key limits_match_policy=/etc/okx-quant/keys/limits-pre-start-public.pem \
  --pre-start-source-public-key release_identity_verified=/etc/okx-quant/keys/release-pre-start-public.pem \
  --target-config /etc/okx-quant/config.yaml \
  --target-env /etc/okx-quant/production.env \
  --runtime-identity /secure-transfer/canary-runtime-identity.json \
  --post-start-verifier-public-key /etc/okx-quant/keys/canary-check-verifier-public.pem \
  --post-start-source-public-key runtime_safety_kernel_live_within_60s=/etc/okx-quant/keys/runtime-source-public.pem \
  --post-start-source-public-key alert_challenge_received=/etc/okx-quant/keys/alert-source-public.pem \
  --post-start-source-public-key backup_exact_version_restored=/etc/okx-quant/keys/restore-source-public.pem \
  --post-start-source-public-key protected_position_or_flat=/etc/okx-quant/keys/account-source-public.pem \
  --post-start-source-public-key rest_ws_reconciliation_safe=/etc/okx-quant/keys/reconciliation-source-public.pem \
  --operator operator@example \
  --risk-approver risk@example \
  --max-slippage 0.005 \
  --output /secure-transfer/transition-request.json

uv run python scripts/canary_artifact.py sign-role \
  --role operator \
  --request /secure-transfer/transition-request.json \
  --private-key /operator-device/canary-private.pem \
  --output /secure-transfer/transition.operator-signature.json
uv run python scripts/canary_artifact.py sign-role \
  --role risk \
  --request /secure-transfer/transition-request.json \
  --private-key /risk-device/canary-private.pem \
  --output /secure-transfer/transition.risk-signature.json
uv run python scripts/canary_artifact.py combine-signatures \
  --request /secure-transfer/transition-request.json \
  --operator-signature /secure-transfer/transition.operator-signature.json \
  --risk-signature /secure-transfer/transition.risk-signature.json \
  --operator-public-key /etc/okx-quant/keys/canary-operator-public.pem \
  --risk-public-key /etc/okx-quant/keys/canary-risk-public.pem \
  --output /etc/okx-quant/canary/transition.json

uv run python scripts/canary_artifact.py request-policy \
  --transition /etc/okx-quant/canary/transition.json \
  --operator-public-key /etc/okx-quant/keys/canary-operator-public.pem \
  --risk-public-key /etc/okx-quant/keys/canary-risk-public.pem \
  --target-config /etc/okx-quant/config.yaml \
  --target-env /etc/okx-quant/production.env \
  --rollback-owner rollback@example \
  --lifetime-seconds 21600 \
  --output /secure-transfer/canary-policy-request.json

uv run python scripts/canary_artifact.py sign-role \
  --role operator \
  --request /secure-transfer/canary-policy-request.json \
  --private-key /operator-device/canary-private.pem \
  --output /secure-transfer/policy.operator-signature.json
uv run python scripts/canary_artifact.py sign-role \
  --role risk \
  --request /secure-transfer/canary-policy-request.json \
  --private-key /risk-device/canary-private.pem \
  --output /secure-transfer/policy.risk-signature.json
uv run python scripts/canary_artifact.py combine-signatures \
  --request /secure-transfer/canary-policy-request.json \
  --operator-signature /secure-transfer/policy.operator-signature.json \
  --risk-signature /secure-transfer/policy.risk-signature.json \
  --operator-public-key /etc/okx-quant/keys/canary-operator-public.pem \
  --risk-public-key /etc/okx-quant/keys/canary-risk-public.pem \
  --output /etc/okx-quant/canary/policy.json
```

transition 会原样复制 epoch 的 `strategy_identity`。生成请求和启动 Gate 都会把
实际 strategy、bar、instrument 集合、interval 和 risk behavior hash 逐项对比，
并把实际校验所得的 source manifest、dependency lock、interpreter、commit、tree
与 epoch exact release 逐项对比；target JSON 的自我声明不能替代这些运行时核验。
Canary operator/risk 同样按派生公钥指纹判重。

再生成并双签最长 6 小时的 Canary policy。机器硬上限为：单笔 ≤25 USDT、≤6 个
intent/小时、并发仓位 1、总敞口 ≤100 USDT、单笔损失 ≤5 USDT、日损 ≤10 USDT、
回撤 ≤2%、滑点 ≤1%。policy 必须更严格或相等，并固定 `production_promotion` 为
`forbidden`。

执行 `scripts/verify_deploy.sh post-start` 后，Canary 必须保持 HALTED。独立 verifier
在 60 秒内读取生成的 runtime status，分别核验五项 check，并使用 transition 已冻结
的 verifier key 签名：

```bash
uv run python scripts/sign_canary_post_start_check.py \
  --check runtime_safety_kernel_live_within_60s \
  --runtime-status /var/lib/okx-quant/admission/canary-runtime-status.json \
  --source-evidence /secure-transfer/runtime-source-evidence.json \
  --source-public-key /etc/okx-quant/keys/runtime-source-public.pem \
  --private-key /verifier-device/canary-check-private.pem \
  --output /secure-transfer/canary-check-runtime.json
```

每份 source evidence 必须绑定 runtime status 中的 `account_uid`、`deployment_unit`、
`demo_soak_epoch_id`、transition/policy/target hashes、runtime instance 和 boot ID。
check verifier 会把 source artifact 原始 bytes 与 source public key 嵌入签名；
activation 运行时会重验 source key 指纹、来源签名和事实语义，尤其禁止用另一账户的
flat/protected 事实开放目标账户 entries。

五个 artifact 必须分别上传 Object Lock，`checks.json` 为每项记录
`passed/observed_at/evidence_uri/evidence_version_id/evidence_sha256/evidence_bytes`。
随后请求、双签并安装一次性 activation：

```bash
uv run python scripts/canary_artifact.py request-activation \
  --transition /etc/okx-quant/canary/transition.json \
  --policy /etc/okx-quant/canary/policy.json \
  --operator-public-key /etc/okx-quant/keys/canary-operator-public.pem \
  --risk-public-key /etc/okx-quant/keys/canary-risk-public.pem \
  --runtime-status /var/lib/okx-quant/admission/canary-runtime-status.json \
  --checks /secure-transfer/checks.json \
  --checks-verifier-public-key /etc/okx-quant/keys/canary-check-verifier-public.pem \
  --minimum-retain-until 2027-08-01T00:00:00+00:00 \
  --kms-key-id EVIDENCE_KMS_KEY_ID \
  --output /secure-transfer/post-start-activation-request.json

uv run python scripts/canary_artifact.py sign-role \
  --role operator \
  --request /secure-transfer/post-start-activation-request.json \
  --private-key /operator-device/canary-private.pem \
  --output /secure-transfer/activation.operator-signature.json
uv run python scripts/canary_artifact.py sign-role \
  --role risk \
  --request /secure-transfer/post-start-activation-request.json \
  --private-key /risk-device/canary-private.pem \
  --output /secure-transfer/activation.risk-signature.json
uv run python scripts/canary_artifact.py combine-signatures \
  --request /secure-transfer/post-start-activation-request.json \
  --operator-signature /secure-transfer/activation.operator-signature.json \
  --risk-signature /secure-transfer/activation.risk-signature.json \
  --operator-public-key /etc/okx-quant/keys/canary-operator-public.pem \
  --risk-public-key /etc/okx-quant/keys/canary-risk-public.pem \
  --output /etc/okx-quant/canary/post-start-activation.json

scripts/verify_deploy.sh post-activate
```

`request-activation` 会对五个 locator 执行 exact-version GET、KMS/COMPLIANCE/
retention 校验；运行时验证双签 activation 和嵌入的 exact bytes，但不会自行持有
S3 权限重新 HEAD 云对象。因此真实 bucket policy、IAM/KMS deny-delete、retention
状态和独立对象存储 verifier attestation 仍是外部门槛，不能由本地签名自证。

Canary 首次启动仍须重新验证真实 UID、`simulated=false`、Read+Trade/Withdraw off、
IP 白名单、journal、limits、release、告警、备份、保护与 REST/WS 对账。任一后续
硬故障都会推进 hard epoch，旧 startup activation 不可再次放行。Demo 30 日和
Canary 成功都不能自动晋级 full production；full production 需要新的独立准入和签名，
不得复用 Canary policy。

## 11. 立即停止条件

出现任一情况立即冻结 entries、Page，并把当天记为 invalid：

- 重复 BUY、UNKNOWN BUY >30 秒或 reconciliation unresolved；
- 非 dust 仓位无 ACTIVE 保护 >10 秒；
- cleanup/余额不闭合、不可恢复 MANUAL_REVIEW；
- 任一 WS 可用性、证据缺口、时钟、RPO、资源或告警硬门失败；
- key/account/release/config/strategy/unit/host identity 与 epoch 不一致；
- signed artifact、hash chain、Object Lock/KMS/exact version 验证失败；
- private key、API secret 或未脱敏 WS payload 进入 evidence。

不得通过删除数据库、删除 invalid 日、重签历史对象、修改 ledger 或扩大 policy 来
“修复”证据。修复代码或冻结身份后，关闭旧 epoch，从新的完整 UTC 日重新计时。
