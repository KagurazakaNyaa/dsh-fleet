# dsh-fleet

Peer-to-peer control plane for [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) (DSH).

多个 DSH 实例互相配对，共享**工作区引用**与在线状态；数据从不复制——会话、文件、模型凭据、插件配置永远留在属主实例上。

> 状态：v0.1。已完成设备身份、配对码、实例登记、探活与打开；peer 通道（`hello` / `workspaces.list` / 签名校验）正在实现。

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

全部同源校验；私钥不出主机进程。

## 路线图

1. **P1 互联**：peer 监听（默认 `127.0.0.1:3071`）、`hello`、`workspaces.list`、签名校验、指纹固定。
2. **P2 呈现**：属主 UI 代理（反代 + `authenticatedUrl`，不落盘），点远程工作区直接打开属主界面。
3. **P3 会话流**：在属主建会话、订阅事件、回传输入与审批，本地只渲染。
4. **P4 网络**：局域网发现、中继、跨网。

## 安全说明

- 配对码泄露等同于“可以被首次配对”，轮换即可；设备公钥固定后，配对码不再参与认证。
- 实例令牌以明文保存在本机 `$DSH_HOME/dsh-fleet/instances.json`，不会发送给模型。
- peer 通道默认只监听回环；打开局域网绑定前请确认网络可信，跨公网请置于 WireGuard/Tailscale 之后。

## License

MIT
