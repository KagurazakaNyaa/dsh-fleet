# dsh-fleet

Peer-to-peer control plane for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) (DSH).

多个 DSH 实例互相配对，共享**工作区引用**与在线状态；数据从不复制——会话、文件、模型凭据、插件配置永远留在属主实例上。

> 状态：v0.1。设备身份、配对码、实例登记、探活、peer 互联（配对 / 工作区目录 / 会话目录 / 授权）、**属主 UI 回环代理（带 token 交接）**、**远程任务（建会话 + 提交 prompt + 事件尾部）**与无头 CLI 已可用；审批回传待做。

## 设计边界

| | 做什么 | 不做什么 |
|---|---|---|
| 控制面 | 设备身份、配对、在线状态、工作区目录（元数据）、路由指令 | — |
| 数据面 | 按需透传到属主（后续阶段） | 不同步会话日志、不同步文件、不建本地索引、不缓存聊天内容 |

推论：

- **工作区在哪台机器，就在哪台机器执行**，因此也用那台机器的模型、配置与插件。
- 远程工作区在本机只是**引用**（`peerId + workspaceId`），不进入原生 workspace 选择器——DSH 的 `workspaceRegistry` 要求本地目录通过 `realpath`。
- 属主离线时只能显示“引用 + 最后已知状态”，不伪造数据。

## 信任模型

| 层 | 机制 |
|---|---|
| Bootstrap | 配对码（96 位随机，可轮换，一次性） |
| 长期身份 | Ed25519 设备密钥；设备 ID = 公钥 SHA-256 指纹 |
| 每次请求 | 签名 method + path + body hash + 时间戳 + nonce，防重放 |
| 授权 | 属主按工作区显式勾选，默认拒绝；认识 ≠ 有权 |

PGP 式“介绍人签名”只会作为便利层（省去手抄指纹），不会因为“被介绍”而自动获得工作区访问权。

## 已实现（v0.1）

- 设备身份：首次启动生成 Ed25519 密钥对，保存在 `$DSH_HOME/dsh-fleet/identity.json`（POSIX 0600）。
- 配对码：独立的 96 位随机码，可在设置页显示/复制/轮换；轮换后旧码立即失效。
- 实例登记：名称、地址、令牌、标签、备注；本地 JSON 持久化。
- 探活：识别 DSH 根页面与 `401 dsh web authentication required`，报告 HTTP 状态与延迟。
- 打开：按令牌拼出登录链接，在新标签页打开对应实例。
- 设置页：「设置 → DSH 集群」。

## Peer 协议（v1）

peer 监听默认 `127.0.0.1:3071`，只承载控制面消息。

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/hello` | 返回 `protocol`、`deviceId`、`name`、公钥（未签名） |
| POST | `/pair` | 携带对端配对码 **或** `dsh web` 启动时打印的 token + Ed25519 签名；成功后双向固定公钥 |
| GET | `/workspaces` | 签名请求；只返回属主已授权的工作区**元数据** |
| GET | `/sessions` | 签名请求；返回属主会话的 ID、标题、目录与运行状态，**不含消息内容**；需 `sessionAccess` |
| GET | `/ui-token` | 签名请求；返回属主自己铸的带 token 登录 URL，供代理首次打开时落 cookie；需 `uiAccess` |
| POST | `/session/create` | 在属主新建会话（`workspaceId`）；需 `sessionAccess` |
| POST | `/session/prompt` | 向属主会话提交 prompt（`sessionId`、`text`）；需 `sessionAccess` |
| GET | `/session/tail` | 从游标读属主会话的新事件（用户/助手/工具/回合结束）；需 `sessionAccess` |
| GET | `/tunnel`（Upgrade） | 签名升级后进入字节隧道；每个流被转发到属主 `127.0.0.1:<web 端口>`，需属主开启 `uiAccess` |

- 每次请求签名 `METHOD\nPATH\nTIMESTAMP\nNONCE\nSHA256(body)`，时间窗 ±60s，nonce 去重防重放。
- 工作区默认不授权；属主在本地勾选后才出现在 `workspaces` 结果里。
- 协议实现见 `peer.js`，自检见 `scripts/peer-smoke.mjs` 与 `scripts/integration-pair.mjs`。

### 两种 bootstrap 凭据

| 凭据 | 从哪来 | 适合 |
|---|---|---|
| 配对码 | 本插件设置页生成，可轮换 | 有 UI 的场景 |
| **启动 token** | `dsh web` 启动后打印的 `?token=…` | **无头 / 纯终端**：没有浏览器也能配对 |

属主进程用 `connection.authenticatedUrl()` 读取自己当前进程的 token（不落盘、不写日志），收到 `x-fleet-token` 后用 `timingSafeEqual` 比对；两者都只是 bootstrap，配对完成后长期认证一律走 Ed25519 签名。

## 无头模式（CLI）

不需要浏览器，直接对正在运行的插件发指令：

```bash
# 看本机设备 ID 与监听状态
dsh-fleet identity --local http://127.0.0.1:3080

# 用对端 dsh web 打印的 token 配对（适合一台机器只有终端）
dsh-fleet pair 192.168.3.245:3071 --token '<启动时打印的 token>' --local http://127.0.0.1:3080

# 或者用配对码
dsh-fleet pair 127.0.0.1:3071 --code ABCD-EF01-... --local http://127.0.0.1:3080

# 查 peer、拉对端工作区、授权本机工作区
dsh-fleet peers --local http://127.0.0.1:3080
dsh-fleet workspaces <deviceId> --local http://127.0.0.1:3080
dsh-fleet sessions <deviceId> --local http://127.0.0.1:3080
dsh-fleet grant <deviceId> <workspaceId> --local http://127.0.0.1:3080
```

`--local` 可省略，默认 `http://127.0.0.1:3080`，也可用 `DSH_WEB_URL` 环境变量。

## DeepSeek Desktop

Desktop 与 `dsh web` 有三点差异，插件都已处理：

| 差异 | 处理 |
|---|---|
| Web 端口每次启动都随机 | 插件把实时地址写入 `$DSH_HOME/dsh-fleet/runtime.json`；CLI 不传 `--local` 也能找到 |
| 没有终端输出启动 token | 配对默认用设置页的配对码；token 只在有终端（`dsh web --no-open`）时可用 |
| 新窗口可能被 Electron 拦截 | 每个实例提供「复制链接」，拿带 token 的地址粘到浏览器即可 |

「本机身份」里直接显示 **Web 地址** 与 **Peer 地址**，都可一键复制；Peer 监听默认 `127.0.0.1`，需要局域网时设 `DSH_FLEET_HOST=0.0.0.0`（并自行确认网络可信），端口用 `DSH_FLEET_PORT` 覆盖。

```bash
node scripts/peer-smoke.mjs          # 两个内存实例互测：配对、授权、重放、坏签名
node scripts/token-pair.mjs          # token 配对、错 token、缺凭据
node scripts/integration-pair.mjs    # 用一个假 peer 验证正在运行的插件
node scripts/host-token.mjs          # 真实主机代码读取自身 token 并完成配对
```

## 安装

```bash
dsh plugin --profile web add /path/to/dsh-fleet
```

或从仓库安装：

```bash
git clone https://github.com/KagurazakaNyaa/dsh-fleet.git
dsh plugin --profile web add ./dsh-fleet
```

安装后重启 `dsh web`；设置页出现「DSH 集群」。

## 接口

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/dsh-fleet/state` | 实例列表 + `DSH_HOME` |
| GET | `/api/dsh-fleet/identity` | 本机设备 ID、公钥、配对码 |
| POST | `/api/dsh-fleet/identity/rotate` | 轮换配对码 |
| POST | `/api/dsh-fleet/save` | 新增/更新实例 |
| POST | `/api/dsh-fleet/delete` | 删除实例 |
| POST | `/api/dsh-fleet/probe` | 探活（单条或全部） |
| POST | `/api/dsh-fleet/launch` | 取带令牌的登录链接 |
| GET | `/api/dsh-fleet/peers` | 已配对 peer + 本机监听状态 |
| POST | `/api/dsh-fleet/pair` | 用地址 + 配对码发起配对 |
| POST | `/api/dsh-fleet/peers/workspaces` | 拉取某 peer 已授权的工作区元数据 |
| POST | `/api/dsh-fleet/peers/grant` | 授权/撤销某个 peer 访问本机工作区 |
| POST | `/api/dsh-fleet/peers/delete` | 删除 peer 记录 |
| POST | `/api/dsh-fleet/peers/ui-access` | 允许/撤销该 peer 访问**本机**界面 |
| POST | `/api/dsh-fleet/peers/ui` | 取该 peer 的界面代理地址（首次建立本机回环端口） |
| POST | `/api/dsh-fleet/peers/session-access` | 允许/撤销该 peer 查看本机会话目录 |
| POST | `/api/dsh-fleet/peers/sessions` | 拉取该 peer 的会话元数据 |
| POST | `/api/dsh-fleet/peers/task` | 在属主建会话并提交一句话，返回 `taskId`/`sessionId` |
| POST | `/api/dsh-fleet/peers/task/poll` | 读取任务的新事件（游标在 Hub 内存中） |
| GET | `/api/dsh-fleet/workspaces` | 本机工作区列表（供授权选择） |

全部同源校验；私钥不出主机进程。

## 路线图

1. **P1 互联**：peer 监听（默认 `127.0.0.1:3071`）、`hello`、`pair`、`workspaces`、签名校验、设置页 peer 面板 —— 已完成。
2. **P2 呈现**：属主 UI 回环代理（隧道 + `uiAccess` 授权，数据只透传）—— 已完成；点「界面」即在本机端口打开属主 DSH。
3. **P3 会话**：会话目录、远端建会话 + 提交 prompt + 事件尾部已完成；审批/提问回传与真流式待做（目前可在属主界面处理审批）。
4. **P4 网络**：局域网发现、中继、跨网。

## 安全说明

- 配对码泄露等同于“可以被首次配对”，轮换即可；设备公钥固定后，配对码不再参与认证。
- 实例令牌以明文保存在本机 `$DSH_HOME/dsh-fleet/instances.json`，不会发送给模型。
- peer 通道默认只监听回环；打开局域网绑定前请确认网络可信，跨公网请置于 WireGuard/Tailscale 之后。
- `uiAccess` 默认关闭；开启等于把本机 DSH 界面（进而 shell）交给该 peer，只对可信设备开启。
- `sessionAccess` 默认关闭；开启后对方可以在本机**新建会话并提交 prompt**，等同于远程指挥 Agent 执行命令，只对可信设备开启。

## License

MIT
