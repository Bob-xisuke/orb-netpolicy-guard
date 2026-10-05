# orb-netpolicy-guard

把网络策略的选路对象、允许与拒绝规则、端口范围以及插件参数记录成可查询的服务，支持按命名空间评估策略覆盖并追溯规则变更。

## 运行要求

- Go 1.26 或以上
- SQLite（本服务自带存储，不需要外部数据库）

## 构建、测试与启动

```bash
go build ./...
go test ./...
go run .
```

服务默认监听 `127.0.0.1:8080`。可用环境变量覆盖：

| 变量 | 默认值 | 用途 |
|---|---|---|
| `ADDR` | `127.0.0.1:8080` | HTTP 监听地址 |
| `DB_PATH` | `orb-netpolicy-guard.db` | SQLite 数据库文件路径 |

## 已公开的入口

### `GET /healthz`

返回服务与存储状态。正常时 HTTP 200：

```json
{"status":"ok","database":"ok"}
```

存储不可用时 HTTP 503：

```json
{"error":{"code":"storage_unavailable","message":"database is not available"}}
```

### `POST /v1/net-policies`

登记一条不可修改的网络策略。请求体是单个 JSON 对象：

```json
{
  "namespace": "payments",
  "name": "default-deny",
  "label": "tier=backend",
  "rules": [{"direction": "ingress", "action": "deny", "ports": [1, 65535]}],
  "pluginParams": {"mode": "enforce"}
}
```

- `namespace`、`name`、`label`：必填的非空白字符串；`namespace` 与 `name` 共同确定记录身份，按原值匹配。
- `rules`：必填的非空数组，顺序有意义。每条规则含 `direction`（`ingress` 或 `egress`）、`action`（`allow` 或 `deny`）、`ports`（两个整数构成的闭区间，1–65535，起点不大于终点）。
- `pluginParams`：必填的字符串键值对象，可为空对象。

首次登记返回 201，响应对象包含提交字段以及 `order`（全局生效顺序，从 1 递增）和 `conflict`（与同命名空间、同标签的已提交记录存在同方向、相反动作且端口重叠的规则时为 `true`）。同身份同内容重试返回 200 与原记录，不占用顺序；同身份不同内容返回 409 与 `NetPolicyConflictError`。输入非法返回 400 与 `InvalidNetPolicyInputError`，不写入任何记录。

### `GET /v1/net-policies`

查询已提交记录。`namespace` 与 `label` 至少提供一个，同时提供时取交集；缺少条件、空白或重复参数返回 400 与 `InvalidNetPolicyInputError`。命中返回 200：

```json
{"items":[{"namespace":"payments","name":"default-deny","label":"tier=backend","rules":[...],"pluginParams":{...},"order":1,"conflict":false}]}
```

`items` 按 `order` 升序排列。无结果返回 404 与 `NetPolicyNotFoundError`。

## 错误约定

所有错误响应都是单个顶层 `error` 对象，包含 `code` 与 `message` 两个字符串字段；`message` 不包含 SQL、堆栈或文件路径。
