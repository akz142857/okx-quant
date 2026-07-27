# 安全模型与威胁分析

## 资产和信任边界

最高价值资产是交易权限、资金、订单/成交事实、审计日志与备份加密口令。OKX 是账户
事实源；本机运行时、SQLite 和私有 WS 是受控组件；行情、新闻、LLM 输出、Webhook
接收端和网络均不可信。策略只能提出意图，不能绕过风险和单写者直接下单。

## 主要威胁与控制

| 威胁 | 影响 | 主要控制 |
|---|---|---|
| API key 泄露 | 非授权交易/资金风险 | env 文件 0640、日志脱敏、独立子账户、Read+Trade、无 Withdraw、IP 白名单、轮换 |
| 重放或重复下单 | 重复持仓 | 发送前持久化、永久唯一 `clOrdId`、POST 不重试、UNKNOWN resolver |
| 进程/主机死亡 | 仓位失去本地保护 | OKX 托管 OCO/conditional、systemd watchdog、独立 heartbeat Page |
| WS 丢失/乱序 | 投影错误 | 状态单调转换、累计成交幂等、重连 REST baseline、周期对账 |
| 本地库损坏/替换/勒索 | 审计串线或恢复丢失 | 原子初始化 marker、不可变账户 UID 绑定、WAL/FULL、本地在线备份、独立身份每日异地加密归档、月度恢复演练 |
| 恶意/错误 LLM 输出 | 越权交易 | 不可信输入封装、结构校验、超时 HOLD、确定性风控、shadow A/B |
| 配置/制品误用 | demo/实盘串线、错策略或超额风险 | 强类型未知字段拒绝、实际源码+策略+周期+参数+风控组合身份 |
| 内部误操作 | 错误恢复 BUY、全仓卖出或取消保护 | 硬状态 epoch/CAS、精确确认词、一次性短效 Ed25519 双人批准、控制队列、审计 |
| 供应链攻击 | 执行恶意代码 | `uv.lock`、CI、固定 action SHA、高危扫描、不可变发布 |

## 密钥生命周期

OKX 密钥只能存在于 OKX 和 `/etc/okx-quant/production.env`，不能写入 Git、SQLite、
日志、备份或故障证据。`okxquant-trader`、`okxquant-watchdog`、
`okxquant-backup` 是不同 Unix 身份：交易进程不读取备份口令，备份与 watchdog
进程不读取 OKX key。轮换时先创建新 key、验证 Read/Trade 和白名单、进入维护模式、
切换服务，确认后撤销旧 key。泄露时立即在 OKX 撤销 key、`halt-entries`、核对全部
订单/algo/fills/余额并保留审计证据。

备份加密口令应由独立 secret manager 管理，不能与 API key 同库存放。生产 profile
强制使用隔离 backup worker，trader 配置禁止持有 offsite URI 或备份口令。对象存储
凭据只授予指定前缀写入/读取权限，并启用版本化、服务端加密和保留策略。签名 ready
manifest 绑定密文哈希、账户、schema 与快照时间，恢复年龄不信任下载后的 mtime。

风险审批 Ed25519 私钥必须由独立审批身份/设备持有，不能出现在交易主机；交易运行时
只读取公钥。批准 artifact 绑定 action、command ID、账户、配置哈希、精确确认词、
有效期；flatten 还绑定交易对集合。SQLite command 主键提供一次性消费语义。

生产准入另有独立签名根：每日 demo 观测由监控身份签名并绑定 S3 对象哈希和 version
ID；最终风险审批签名绑定 evidence SHA-256、30 日 ledger head、commit/runtime
identity/account 与批准预算。runtime identity 由实际导入源码摘要、策略、非秘密参数、
bar、交易对、调度周期和生产风控共同计算，REVISION 只作标签。root-owned 公钥及目录
不可被服务账号写入。唯一 production launcher 在每次启动时用同一个
root-owned manifest 与实际源码计算身份，并由受控 venv Python 直接执行同发布目录
`main.py` 的精确 live argv；生产路径不信任可替换的 console wrapper，且消除了
precheck 与真实 CLI 参数的双录入。首次激活只能在短效 evidence/approval 窗口内由 root 写入
durable deployment receipt；以后仅同一不可变身份可重启，既不会因批准到期阻断已有
仓位安全内核，也不能用旧 receipt 启动新代码/配置。因此自填 JSON、重算本地 hash
chain 或直接重启服务均不能构造准入。

身份包含完整脱敏配置（只脱敏真正 secret key，不抹除 token budget）、有序交易集合、
`pyproject.toml`/`uv.lock`、Python 启动路径/链接目标/解释器字节，以及实际安装
distribution 依赖闭包。
主进程内部再次执行同一 receipt/manifest 校验，不能靠直接调用 console script 绕过。
receipt 或历史材料损坏时只允许持久 hard-safe 的 safety-only 恢复/保护/退出内核；
普通状态会锁存 `HALTED`，既有 `EMERGENCY_EXIT`/`MAINTENANCE` 不会被降级覆盖。
该内核不可被 resume 提升为 READY，并会忽略 shadow 配置以保留真实保护/退出能力。
production 账户中 manifest 外的已有仓位也不会被扩展成新的策略 BUY worker。

## 残余风险

- 交易所、网络分区或极端跳空可能让止损成交价偏离触发价。
- SPOT 市价卖出的数量单位与最新 `slippagePct` 约束仍需每个 API 版本做 demo 契约
  验证；保护单和仓位上限是额外防线。
- SQLite 单机适合小规模单写者；若无法满足异地 5 分钟 RPO 或写入规模增长，应迁移
  托管 PostgreSQL。
- 代码门禁不证明策略盈利，也不能替代连续 demo、canary 和人工风险审批。
