# OKX Quant 生产运行手册

更新时间：2026-07-27

本文面向值班维护者。任何时候都优先保护已有仓位，再考虑恢复新增交易。交易所余额、
订单、成交和保护单是最终事实；本地数据库是持久化意图、投影与审计记录，禁止用旧
数据库覆盖交易所的新事实。

## 1. 安全边界

- 生产只使用独立子账户，API key 仅授予 Read + Trade，必须关闭 Withdraw 并设置
  IP 白名单。
- demo、shadow、canary、production 使用不同 key、数据库、目录和配置。
- `READY` 才允许 BUY；`DEGRADED`、`HALTED`、`EMERGENCY_EXIT` 仍允许退出。
- 普通策略线程不直接访问下单 API；所有写操作经过持久化单写者。
- `UNKNOWN` 表示“交易所可能已接受”，只能通过 `clOrdId` 查询和对账，禁止重下。
- 非 dust 仓位必须有 ACTIVE 交易所保护单，否则进入紧急模式并告警。

## 2. 首次部署

以 root 完成一次性安装。交易、watchdog、备份分别使用不同非 root 身份，只共享
只读数据组；任何一个服务都不能同时获得 OKX 交易密钥和备份加密口令：

```bash
groupadd --system okxquant-data
useradd --system --user-group --home /var/lib/okx-quant --shell /usr/sbin/nologin okxquant-trader
useradd --system --user-group --home /nonexistent --shell /usr/sbin/nologin okxquant-watchdog
useradd --system --user-group --home /var/lib/okx-quant-backup --shell /usr/sbin/nologin okxquant-backup
usermod -a -G okxquant-data okxquant-trader
usermod -a -G okxquant-data okxquant-watchdog
usermod -a -G okxquant-data okxquant-backup
install -d -o root -g root -m 0755 /opt/okx-quant
install -d -o root -g okxquant-data -m 0750 /etc/okx-quant /etc/okx-quant/keys /etc/okx-quant/admission
install -d -o okxquant-trader -g okxquant-data -m 2750 /var/lib/okx-quant/production
install -d -o root -g okxquant-data -m 0750 /var/lib/okx-quant/admission
# 此挂载点必须是有 quota/监控的独立文件系统，不得与交易库同盘。
mount /dev/<dedicated-backup-volume> /var/lib/okx-quant-backup
install -d -o okxquant-backup -g okxquant-data -m 0750 /var/lib/okx-quant-backup/daily
install -d -o okxquant-trader -g okxquant-data -m 0750 /var/log/okx-quant
```

`production` 目录的 `2750` setgid 位与账本的
`okxquant-trader:okxquant-data 0640` 是强制边界：trader 可写，watchdog/backup
两个隔离身份只能读。不得把账本收紧为 `0600`，否则独立心跳审计与异地归档都会失去
数据库视图。

发布目录采用不可变版本并由 `/opt/okx-quant/current` 原子指向当前版本。把以下模板
安装到对应位置：

- `deploy/config.production.yaml.example` → `/etc/okx-quant/config.yaml`
- `deploy/production.env.example` → `/etc/okx-quant/production.env`
- `deploy/watchdog.env.example` → `/etc/okx-quant/watchdog.env`
- `deploy/backup.env.example` → `/etc/okx-quant/backup.env`
- `deploy/launch.production.json` → `/etc/okx-quant/launch.json`
- `deploy/systemd/*.service`、`*.timer` → `/etc/systemd/system/`
- `deploy/logrotate/okx-quant` → `/etc/logrotate.d/okx-quant`

`production.env`、`watchdog.env`、`backup.env` 分别必须是
`root:okxquant-trader`、`root:okxquant-watchdog`、`root:okxquant-backup` 的 `0640`
文件；生产 env 禁止出现备份口令，备份/watchdog env 禁止出现 OKX key。主机必须启用
NTP/chrony、SSH key 登录、防火墙和安全更新。仅将 `127.0.0.1:9108` 通过受控监控代理
采集，不直接暴露公网。

风险审批人在独立身份/设备上生成 Ed25519 密钥；私钥不得复制到交易主机、交易
服务账号或 operator 可写目录。控制批准、生产准入批准、demo 观测分别使用独立公钥，
全部由 root 持有且 group/other 不可写。控制公钥安装为
`/etc/okx-quant/keys/control-approval-public.pem`，并在生产配置中设置
`resume_approval_public_key`。

备份 worker 使用专属 Ed25519 身份签发归档 ready manifest。私钥只允许
`root:okxquant-backup 0640`，公钥必须 `root:root 0644`，并且不得复用控制、准入或
demo 观测密钥：

```bash
openssl genpkey -algorithm Ed25519 -out /etc/okx-quant/keys/backup-manifest-private.pem
openssl pkey \
  -in /etc/okx-quant/keys/backup-manifest-private.pem \
  -pubout -out /etc/okx-quant/keys/backup-manifest-public.pem
chown root:okxquant-backup /etc/okx-quant/keys/backup-manifest-private.pem
chmod 0640 /etc/okx-quant/keys/backup-manifest-private.pem
chown root:root /etc/okx-quant/keys/backup-manifest-public.pem
chmod 0644 /etc/okx-quant/keys/backup-manifest-public.pem
```

新账户首次部署必须显式初始化交易日志；生产 `live` 对缺失、符号链接或零长数据库
一律拒绝启动，绝不会静默创建空账本。初始化在临时库中以单事务写入不可变账户 UID、
初始化 marker 与 `HALTED`，fsync 后才原子安装；后续启动会在任何 REST 恢复和策略
执行前校验日志绑定账户：

```bash
sudo -u okxquant-trader okx-quant \
  --env-file /etc/okx-quant/production.env \
  --config /etc/okx-quant/config.yaml \
  init-journal \
  --actor "bootstrap-operator@example" \
  --owner-user okxquant-trader \
  --owner-group okxquant-data \
  --confirm "INIT <production.account_id>"
```

若账户曾经交易过或这是灾备恢复，禁止执行 `init-journal`；必须从最近的已验证异地
备份恢复，再以 `HALTED` 对账。

## 3. 发布前检查

```bash
OKX_QUANT_ENV_FILE=/etc/okx-quant/production.env \
OKX_QUANT_SERVICE=okx-quant \
/opt/okx-quant/current/scripts/verify_deploy.sh preflight
```

`preflight` 不启动服务，验证的是磁盘上即将部署的版本。第 10 节的时间证据和双人签名
准入完成后，先启用隔离服务，再运行 post-start：
CI 生成的 `fault-injection.json` 与 `REVISION` 会一同封入发布压缩包；preflight
复核其 commit/tree、全源码/脚本/测试 manifest 和 OS 故障结果，不依赖部署目录存在
`.git`。缺少该 CI artifact、源码 manifest 不一致或 evidence 非零退出都会拒绝发布。

```bash
systemctl enable --now okx-quant-watchdog.service okx-quant-daily-backup.timer
/opt/okx-quant/current/scripts/verify_deploy.sh post-start
```

`post-start` 会明确 restart trader，将实际源码/策略/周期/参数组合身份与准入 evidence
比较，并检查 ready/metrics、watchdog、timer、独立备份文件系统和一次真实 S3 归档。
不得用仍在内存运行的旧版本 ready probe 为磁盘上的新发布背书。
首次 restart 的 root `ExecStartPre` 只在短效 evidence/approval 都有效时原子创建
`/var/lib/okx-quant/admission/deployment-receipt.json`（root-owned 0644）。以后相同
源码、完整配置、launch manifest、evidence 和批准 artifact 的重启只复核 receipt，
不重新按当前时间拒绝已经合法激活的部署；任一身份或 artifact 改变都会要求新的
有效证据/批准并替换 receipt。风险批准公钥轮换时必须保留能验证当前 receipt 所引用
批准的历史公钥，直到该 deployment 完成受控升级。

receipt、历史批准、evidence 或 launch manifest 缺失/损坏时，root activation precheck
允许失败，唯一 launcher 会用受控 venv Python 直接执行同发布目录 `main.py` 并降级
为 `--safety-only`，不会执行 console wrapper。主进程自身再次复核全部身份，
持久锁存 `HALTED`，只启动恢复、对账、保护、告警和退出所需 safety kernel，绝不创建
策略 worker 或 BUY；safety-only 不接受任何 resume/READY 提升，并强制保留真实保护/
退出能力，即使批准配置原为 shadow。`post-start` 会拒绝发布并非零退出，但只要
`healthz` 存活且状态为 HALTED/EMERGENCY_EXIT/MAINTENANCE，就保留该保护内核并 Page，
不会为了发布失败杀死保护/强平流程。因此短效材料故障不能阻断已有仓位保护。直接绕过 launcher 调用
生产 `okx-quant live` 也会被同一进程内门禁降为 safety-only。

还必须人工保存以下外部证据：

1. OKX 子账户名称、key 指纹、Read/Trade 权限、Withdraw 关闭截图；
2. IP 白名单截图及主机出口 IP；
3. 异地对象存储写入和从空目录下载成功记录；
4. 告警接收人和值班升级路径；
5. `docs/RELEASE_CHECKLIST.md` 的审批。

不能从代码推断 key 权限。缺少任一证据时只能运行 demo/shadow。

## 4. 启动、停止与健康检查

```bash
systemctl daemon-reload
systemctl enable --now okx-quant.service
systemctl enable --now okx-quant-watchdog.service
systemctl enable --now okx-quant-daily-backup.timer
systemctl status okx-quant.service
curl --fail http://127.0.0.1:9108/readyz
curl --fail http://127.0.0.1:9108/metrics
okx-quant --env-file /etc/okx-quant/production.env \
  --config /etc/okx-quant/config.yaml production-status
```

正常启动顺序是：进程锁 → schema/migration → 时钟检查 → REST recovery/reconciliation
→ 私有 WS 订阅及 baseline → `READY`。启动卡在任一步都不会开放 BUY。

普通维护先执行 `halt-entries`，确认现有保护单 ACTIVE 后再停止服务：

```bash
okx-quant --env-file /etc/okx-quant/production.env \
  --config /etc/okx-quant/config.yaml \
  halt-entries --actor "operator@example"
okx-quant --env-file /etc/okx-quant/production.env \
  --config /etc/okx-quant/config.yaml production-status
systemctl stop okx-quant.service
```

`HALTED` 会跨断线、对账和重启锁存，后台任务不能自动解除。维护完成并重新启动服务后，
由 operator 先生成绑定账户、配置哈希、命令 ID、精确确认词和 10 分钟内有效期的
请求：

```bash
okx-quant --env-file /etc/okx-quant/production.env \
  --config /etc/okx-quant/config.yaml \
  resume-request \
  --actor "operator@example" \
  --expires-in 300 \
  --output /secure-transfer/resume-request.json
```

独立 risk approver 在不具备交易服务凭据的审批设备上核对请求，再用其私钥签名：

```bash
python scripts/sign_resume_approval.py \
  --request /secure-transfer/resume-request.json \
  --private-key /risk-controlled/risk-approver-private.pem \
  --approver "risk@example" \
  --output /secure-transfer/resume-approval.json
```

operator 将批准文件送回交易主机并提交；批准文件只能被其绑定的 command ID 消费
一次，过期、账户/配置错配、篡改或重复提交都会失败：

```bash
okx-quant --env-file /etc/okx-quant/production.env \
  --config /etc/okx-quant/config.yaml \
  resume-entries \
  --approval /secure-transfer/resume-approval.json \
  --confirm "RESUME <production.account_id>"
```

唯一写者会重新验证 OKX UID、时钟、告警链、私有 WS baseline、事件序列、完整 REST
对账和保护覆盖，并向 Page webhook 发送同步 challenge；未收到成功 HTTP ACK 时
保持 `HALTED`。事件序列校验与 `READY` 切换位于同一私有事件 fence，不能在两者间
插入余额/订单事件；硬状态使用单调 epoch 做 CAS，恢复期间新到达的 `halt` 会使旧
恢复请求失败。两名身份由 Ed25519 签名强制分离，不是两个可伪填字符串。
`EMERGENCY_EXIT` 不能直接 resume，必须先完成退出或人工裁决。

## 5. Kill switch

停止新增风险但维持保护：

```bash
okx-quant --env-file /etc/okx-quant/production.env \
  --config /etc/okx-quant/config.yaml \
  halt-entries --actor "operator@example"
```

取消普通挂单并退出持仓是破坏性资金动作，也必须走独立签名批准。operator 先生成
绑定具体交易对集合的短效请求；不传 `--inst` 明确表示批准退出全部持仓：

```bash
okx-quant --env-file /etc/okx-quant/production.env \
  --config /etc/okx-quant/config.yaml \
  flatten-request \
  --actor "operator@example" \
  --inst BTC-USDT \
  --output /secure-transfer/flatten-request.json

python scripts/sign_resume_approval.py \
  --request /secure-transfer/flatten-request.json \
  --private-key /risk-controlled/risk-approver-private.pem \
  --approver "risk@example" \
  --output /secure-transfer/flatten-approval.json

okx-quant --env-file /etc/okx-quant/production.env \
  --config /etc/okx-quant/config.yaml \
  flatten-and-cancel \
  --inst BTC-USDT \
  --approval /secure-transfer/flatten-approval.json \
  --confirm "FLATTEN <production.account_id>"
```

命令只写入持久化控制队列，由持有进程锁的交易进程执行。若结果为 `pending`，不得
再次提交；先检查服务是否存活及 `control_commands` 状态。若为 `failed`，立即人工
检查交易所普通订单、algo 订单和余额。

## 6. 事故处置

### UNKNOWN 普通订单

1. 执行 `halt-entries`。
2. 用 `audit-order <clOrdId>` 查看完整链。
3. 在 OKX 按同一 `clOrdId` 查询详情、历史和 fills。
4. 运行 `reconcile-now --wait 30`。
5. 未得到“明确不存在”前绝不重下；超过 30 秒升级 Page。

### 有仓位但无 ACTIVE 保护

1. 系统应自动进入 `EMERGENCY_EXIT` 并发送 Page。
2. 核对 `orders-algo`、余额冻结和当前仓位。
3. 不要同时在 dashboard、CLI 和 OKX UI 发起多个 SELL。
4. 若自动紧急退出失败，按双人流程在 OKX UI 人工退出并记录外部成交，再运行对账。

### 私有 WS 断线

BUY 会被冻结。只要 REST 可用，周期对账和退出路径继续运行。等待重连后的 REST
baseline 完成；在 `/readyz` 恢复 200 前不得人工强制改成 READY。WS 与 REST 同时
不可用时立即 Page。

### 数据库写失败、只读或磁盘满

1. 停止新增风险，确认交易所保护单仍在。
2. 不删除交易日志、WAL 或最新备份来腾空间。
3. 扩容或清理可重建的行情缓存/旧程序包。
4. `PRAGMA integrity_check`、在线备份与恢复演练通过后再启动。

### 时钟偏差

启动偏差超过 1 秒会失败。检查 `timedatectl` 与 chrony；禁止通过放宽限制绕过。

### LLM 或策略线程超时

信号降级为 HOLD，不影响交易所保护和退出。若持续发生，禁用相应 LLM 策略并保留
输入、模型版本、延迟和错误证据。

## 7. 对账与审计

```bash
okx-quant --config /etc/okx-quant/config.yaml reconcile-now --wait 30
okx-quant --config /etc/okx-quant/config.yaml audit-order <clOrdId>
```

任意订单应能串联 decision → intent → state events → fills → position →
protection。外部订单/成交会被导入并标记；重大数量差异进入人工复核，不允许静默抹平。

## 8. 备份和恢复演练

交易进程每 5 分钟只生成本地 SQLite online backup；独立 `okxquant-backup` 身份也按
5 分钟 timer 从只读数据库生成 AES-256/PBKDF2 加密归档并上传 S3。交易进程看不到备份口令，备份
进程看不到 OKX key。归档只有在完整性、schema 与 account identity 校验通过后才原子
发布；失败会 Page。交易 intents、fills、events 永不自动删除。

立即备份：

```bash
okx-quant --config /etc/okx-quant/config.yaml backup-now
```

每月至少一次从异地同时下载 `.db.enc` 与同名 `.manifest.json` 签名 ready marker，
并在隔离目录验证：

```bash
python scripts/restore_drill.py \
  /path/from/offsite/trading-YYYYMMDDTHHMMSSZ.db.enc \
  --expected-account-id '<production.account_id>' \
  --expected-schema-version 9 \
  --manifest-public-key /etc/okx-quant/keys/backup-manifest-public.pem \
  --expected-signing-key-id backup-signing-2026q3 \
  --expected-encryption-key-id backup-aes-2026q3 \
  --max-rto-seconds 1800 \
  --output evidence/restore-drill-YYYY-MM.json
```

恢复只承认签名 manifest 已发布的密文；manifest 绑定密文 SHA-256、账户、schema、
快照开始/完成和发布时间，RPO 年龄按最保守的快照开始时间计算，不信任下载后的
mtime。归档发布前会真实解密并重跑完整性/身份检查；本地保留采用 24 小时全量、
2–7 日每小时、之后每日的分层策略，上传失败也会 prune。磁盘低于 5 GiB 或数据库
三倍临时空间时 fail closed 并 Page。

`restore_drill.py` 输出明确标记为 `database_restore_component_only`，其计时不包含
异地下载和空机安装，不能冒充整机 RTO。完整演练必须由值班人员从空主机开始计时，
绑定 S3 URI/version ID、下载记录、不可变 release SHA、配置/密钥安装、该组件报告、
MAINTENANCE 启动和只读对账证据。目标是在 30 分钟内完成全部步骤。恢复后先
以 `MAINTENANCE`/HALTED 启动并对账，禁止直接开放 BUY。

正式冷恢复使用受控安装器，不允许手工复制数据库。先停止交易服务，并确认目标路径：

```bash
systemctl stop okx-quant.service
systemctl is-active okx-quant.service  # 必须不是 active

python scripts/cold_restore.py \
  /path/from/offsite/trading-YYYYMMDDTHHMMSSZ.db.enc \
  --target /var/lib/okx-quant/production/trading.db \
  --expected-account-id '<production.account_id>' \
  --expected-schema-version 9 \
  --manifest-public-key /etc/okx-quant/keys/backup-manifest-public.pem \
  --expected-signing-key-id backup-signing-2026q3 \
  --expected-encryption-key-id backup-aes-2026q3 \
  --actor 'operator@example' \
  --owner-user okxquant-trader \
  --owner-group okxquant-data \
  --replace-existing \
  --confirm 'REPLACE /var/lib/okx-quant/production/trading.db WITH ACCOUNT <production.account_id>' \
  --output evidence/cold-restore-YYYY-MM-DD.json
```

安装器在与目标相同的文件系统中解密和复验，先把恢复库持久锁存为
`MAINTENANCE`、递增 mode epoch、写入审计事件和 `fsync`；旧库会先完成 WAL
checkpoint 和完整性检查，再保留为带时间戳的 `pre-cold-restore` 自包含文件，最后
以全流程唯一一次原子 rename 接管。任何切换前故障都不会让规范目标路径消失，也
不会把旧 WAL 应用到新库。

安装完成仍必须以 safety-only 启动，执行只读联合对账并取得双人签名 resume；安装器
不会自动启动服务或开放 BUY。

签名和加密 key 必须分别有不可复用的版本 ID。轮换时先发布新 key、保留旧公钥和旧
passphrase 的 secret-manager 版本至少覆盖最长归档保留期，再同时更新 backup env
中的两个 key ID。恢复时先读 manifest 的 key ID，选择对应历史公钥/口令并显式传入
expected ID；禁止总是使用“current”覆盖旧 key。重叠期内必须各抽取一份新旧归档完成
异地恢复后才能销毁旧 key。

## 9. 升级与回滚

1. `halt-entries` 并确认保护单。
2. 创建在线和异地备份。
3. 在 demo 使用相同提交运行 CI、故障注入、契约测试。
4. 切换不可变发布软链并启动。
5. 确认进程以 `HALTED` 存活、保护单正常，再按签名双人流程执行 `resume-entries`。
6. 等待命令完成和 ready probe 恢复 200；失败时保持 HALTED，禁止直接改库。

schema 迁移 forward-only，启动前自动备份。代码回滚只允许回到兼容当前 schema 的
版本；禁止把旧交易库覆盖到新成交之上。若版本不兼容，保持 HALTED 并前滚修复。

## 10. Demo、shadow 与 canary

OKX demo 契约需人工显式执行。脚本会先验证生产采用的“成交后独立 OCO”，再探测
quote 金额 attached TP/SL，并在最后撤销保护和清仓：

```bash
python scripts/demo_contract.py \
  --config /etc/okx-quant/demo.yaml \
  --confirm I_UNDERSTAND_DEMO_TRADES \
  --output evidence/demo-contract.json \
  --fixture-output evidence/okx-demo-contract-fixture.v1.json
```

fixture 只会在独立 OCO、attached 探测和清理全部成功后生成；订单、algo、trade 和账户
标识会替换成保持引用关系的稳定 token。仓库中的单元测试只能证明录制/脱敏/回放工具，
不能替代这份真实 OKX demo capture。

研究输入先用 `build_dataset_provenance()` 生成 v2 embedded source artifact，上传后
绑定 exact S3 URI/version/bytes SHA。独立研究审批人必须在参数评估开始前使用
`scripts/sign_research_artifact.py` 签署 grid、策略 family、压力场景和两份 exact
dataset locator 的预注册 policy；压力运行完成后，由独立 runner 对完整 stress
evidence hash 再签 attestation。生产 Gate 使用
`/etc/okx-quant/keys/research-policy-public.pem` 同时验证二者，不能在看到结果后缩小
参数网格、替换数据对象或手填压力损失。`ADMISSION_EVIDENCE.example.json` 是包含
placeholder 的字段模板，按设计不可直接准入，producer 输出必须整体替换对应字段。

连续运行证据必须由独立监控身份对每日请求做 Ed25519 签名，再使用
`scripts/production_gate.py record` 实时结算。每行同时绑定 S3 URI、对象 SHA-256、
S3 version ID、durable SLO 日报告 SHA-256、提交、配置、账户和至少 20 小时观测
窗口；本地重算哈希链不能替代监控签名，禁止事后回填。

先从交易数据库的 durable events 生成不可手填的 UTC 日报告：

```bash
python scripts/slo_report.py \
  --database /var/lib/okx-quant/production/trading.db \
  --day 2026-07-27 \
  --output evidence/slo-2026-07-27.json
```

独立监控端上传包含该报告的日证据对象，生成的 anchor request 必须包含报告文件
SHA-256，以及保护/滑点样本数和滑点 max。签名后再结算；命令行数值必须与报告中的
保护 p99、滑点 p99 和未解释对账差异完全一致。record 会从同一报告写入样本数和
max；无成交日可以记录零样本，但不会贡献最终至少 30 个保护与 30 个滑点样本的累计
门槛，任一成交的 max 滑点越界都会中断 clean streak：

```bash
python scripts/production_gate.py \
  --ledger /var/lib/okx-quant/admission/demo-observations.json \
  record \
  --day 2026-07-27 \
  --mismatches 0 \
  --protection-p99 2.4 \
  --slippage 0.0012 \
  --git-commit '<40-hex-release-commit>' \
  --config-hash '<64-hex-runtime-config-hash>' \
  --account-id '<okx-account-uid>' \
  --source-uri 's3://bucket/demo-days/2026-07-27.json' \
  --source-sha256 '<64-hex-object-sha>' \
  --source-version-id '<immutable-s3-version-id>' \
  --slo-report evidence/slo-2026-07-27.json \
  --anchor evidence/demo-anchor-2026-07-27.json \
  --observation-public-key /etc/okx-quant/keys/demo-monitor-public.pem \
  --observation-started-at '2026-07-27T00:00:00+00:00' \
  --observation-ended-at '2026-07-27T23:00:00+00:00'
```

最终 evidence metadata 的 `monitor_key_fingerprint` 必须是上述实际公钥文件字节的
SHA-256；更换监控 key 后应作为证据身份变更重新开始观察。

连续 30 日与全部研究/工程/运维检查通过后，operator 先生成准入根请求：

```bash
# 先计算实际部署身份，并把输出的 config_hash 写入 evidence metadata 和每日观测锚。
python scripts/production_launch.py \
  --config /etc/okx-quant/config.yaml \
  --release-commit-file /opt/okx-quant/current/REVISION \
  --launch-manifest /etc/okx-quant/launch.json \
  --identity-only

python scripts/production_gate.py \
  --ledger /var/lib/okx-quant/admission/demo-observations.json \
  request \
  --evidence /etc/okx-quant/admission/evidence.json \
  --max-slippage 0.01 \
  --approved-max-stress-loss 100 \
  --observation-public-key /etc/okx-quant/keys/demo-monitor-public.pem \
  --research-public-key /etc/okx-quant/keys/research-policy-public.pem \
  --config /etc/okx-quant/config.yaml \
  --release-commit-file /opt/okx-quant/current/REVISION \
  --launch-manifest /etc/okx-quant/launch.json \
  --output /secure-transfer/admission-request.json
```

风险审批人在独立设备检查全部证据后，用 `scripts/sign_admission_approval.py` 签名。
签名 artifact 绑定证据文件哈希、30 日 ledger head、commit/config/account 和两项预算。
其中 config identity 覆盖实际导入的 Python 源码摘要、策略名、非秘密策略参数上下文、
K 线周期、实际交易对、调度周期和生产风控；仅复制/改写 REVISION 不能让另一份代码
或策略复用批准。制品身份还绑定 `pyproject.toml`、`uv.lock`、Python 启动路径/
链接目标/解释器字节和已安装运行时依赖闭包的实际文件字节；共享 venv 中任何依赖
或解释器替换都会使 receipt 失效。
CI 发布压缩包自带根目录 `REVISION`，部署时随不可变 release 原子切换。
将 artifact 只读安装到 `/etc/okx-quant/admission/approval.json`；systemd
唯一的 `production_launch.py` 入口会读取 root-owned launch manifest、重新评估并
验证 root 激活的 deployment receipt，然后用同一份已验证对象 `exec` live；systemd
不再双录 strategy/bar/inst 参数。首次激活脚本才会重放完整 30 日 gate 和短效批准。
不能跳过该入口直接启动生产 trader。任何
commit/config/account、ledger head 或预算变化都会使批准失效。
