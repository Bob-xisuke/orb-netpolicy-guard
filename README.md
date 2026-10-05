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

登记一条不可修改的网络策略。请求体必须是**单个** JSON 对象，字段如下：

| 字段 | 类型 | 约束 |
|---|---|---|
| `namespace` | 字符串 | 必填，非空白 |
| `name` | 字符串 | 必填，非空白 |
| `label` | 字符串 | 必填，非空白 |
| `rules` | 数组 | 必填，非空；每项见下 |
| `pluginParams` | 对象 | 必填，键值均为字符串，可为空对象 `{}` |

每条规则的字段：

| 字段 | 类型 | 约束 |
|---|---|---|
| `direction` | 字符串 | 必填，`ingress` 或 `egress` |
| `action` | 字符串 | 必填，`allow` 或 `deny` |
| `ports` | 两个整数构成的数组 | 必填，闭区间，端点均在 `1..65535`，起点不大于终点 |

记录身份由 `namespace` 与 `name` 共同确定，字符串按原值匹配（不做 trim）。登记成功返回提交的全部字段，并额外包含：

- `order`：全局序号，从 1 开始，按新记录生效顺序递增；
- `conflict`：见下文冲突判定。

```json
{
  "namespace": "team-a",
  "name": "web-policy",
  "label": "frontend",
  "rules": [{"direction": "ingress", "action": "allow", "ports": [80, 90]}],
  "pluginParams": {"mode": "enforce"},
  "order": 1,
  "conflict": false
}
```

登记语义：

- 身份不存在：HTTP 201，创建新记录并占用下一个 `order`。
- 身份已存在且内容完全相同：HTTP 200，返回原记录，不占用新顺序（幂等重试）。
- 身份已存在但内容不同：HTTP 409 `NetPolicyConflictError`，旧记录保持不变。
- 内容比较时对象键的顺序无关（`pluginParams`），但 `rules` 数组的顺序有关。
- 若新记录与生效前已提交的**同命名空间、同 label** 记录之间，存在同方向、相反动作且端口区间重叠的规则，则新记录的 `conflict` 为 `true`，否则为 `false`；该标记只描述新记录，旧记录不改动。
- 任何校验失败都不会写入数据；并发提交同一身份只会保存一条记录；重启并重新打开同一数据库后，记录仍然存在。

### `GET /v1/net-policies`

查询已提交的记录，至少提供 `namespace` 或 `label` 之一，同时提供时取交集：

```
GET /v1/net-policies?namespace=team-a
GET /v1/net-policies?label=frontend
GET /v1/net-policies?namespace=team-a&label=frontend
```

命中时 HTTP 200，返回 `items` 数组，按 `order` 升序排列：

```json
{"items":[{"namespace":"team-a","name":"web-policy","label":"frontend","rules":[{"direction":"ingress","action":"allow","ports":[80,90]}],"pluginParams":{"mode":"enforce"},"order":1,"conflict":false}]}
```

## 错误约定

所有错误响应都是单个顶层 `error` 对象，包含 `code` 与 `message` 两个字符串字段；`message` 不包含 SQL、堆栈或文件路径。

| HTTP | `error.code` | 触发场景 |
|---|---|---|
| 400 | `InvalidNetPolicyInputError` | POST：正文不是单个合法 JSON、字段缺失/类型不符、名称或标签为空白、非法枚举、端口范围非法；GET：缺少 `namespace`/`label`、值为空白、查询参数重复 |
| 404 | `NetPolicyNotFoundError` | GET 查询条件合法但没有任何已提交记录命中 |
| 409 | `NetPolicyConflictError` | POST 身份已存在但提交内容与原记录不同 |
| 404 | `route_not_found` | 未知路径 |
| 503 | `storage_unavailable` | 存储不可用（含 `/healthz` 与两个策略入口） |
