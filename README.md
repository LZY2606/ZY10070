# Zone Cutover Simulator（DNS zone 分阶段发布模拟器）

在真正改动权威 zone 文件**之前**，模拟以下因素叠加后的解析后果：

- **TTL 与递归缓存残留**：递归节点独立缓存正/负答案，严格按已发出的 TTL 过期；切回旧记录也要等旧 TTL，旧值不会“瞬间回来”。
- **权威服务器不同步**：每个权威节点对同一阶段有独立的传播延迟，切换窗口内不同递归节点可能向不同版本的权威取到不同答案。
- **递归缓存 + 时钟偏差**：每个递归节点有独立缓存与恒定时钟偏差；偏差同时影响 RRSIG 的签名有效/过期判断。
- **DNSSEC 签名窗口**：相邻两个有效 zone 中覆盖同一 rrset 的 RRSIG 时间窗必须相交，否则判定为“签名窗口不相交”。
- **委派、通配符、CNAME 链**：解析器支持非顶点 NS 委派（含 in-bailiwick glue 校验）、RFC 4592 通配符、CNAME 跟随与循环检测。

关键判定（解析、四项安全阻断、时间冲突、解析、收敛、确定性）全部在 **Go 后端**；浏览器只是视图。

---

## 安装与运行

仅依赖 Go 标准库，无第三方模块。

```bash
go mod download
go test ./... -count=1
go run ./cmd/server --listen 127.0.0.1:5205
```

浏览器固定打开：**http://127.0.0.1:5205**

可选参数：`--data ./data`（持久化目录，默认 `./data`）。

### 页面演示步骤

1. 左栏「导入 Zone」点 **载入示例**，`kind=current` 后点 **解析并导入**；切到 `kind=candidate` 再载入/导入一次。示例包含：`www` 改地址、`old` 删除（演示负缓存）、`new` 新增、`*.svc` 通配符改地址、`api CNAME www`。
2. 「发布计划」点 **按 current→candidate 生成计划**。安全时状态为 `ready`；若存在阻断，页面会列出红色原因且该计划无法模拟。
3. 「模拟参数」设置权威/递归节点数、延迟、时钟偏差与**显式种子**，点 **运行 / 复用模拟**。
4. 拖动顶部时间轴：对同一查询，每个递归节点显示其答案以及来源标签：
   - `authoritative`（向权威实时取）、`cache`（正缓存命中）、`negative cache`（NXDOMAIN/NODATA 负缓存，TTL 取 SOA minimum）。
   - 每条结果带 `valid / expired / not_yet_valid / unsigned / insecure` 签名状态与应答权威节点 ID。
5. 「所有节点最早收敛」给出全部递归节点从某一时刻起持续等于最终答案的最早秒数（要求贯穿到时间轴末尾，保证缓存也已刷新）。
6. 「阶段与决策」用按钮按最早合法时间推进；可「立即回滚」。回滚后的模拟里，旧记录必须再等一轮传播 + 已发出的 TTL 才会全量恢复。
7. 「复制此计划」生成新文档：旧模拟仍绑定旧 zone/计划指纹；修改后的副本得到新指纹，不会复用旧结果。
8. 「导出完整证据」生成包含每条查询每个节点每个探针的证据、阶段决策与操作事件的 JSON 包。

---

## 数据模型（三类数据分开保存）

持久化根目录（默认 `./data`）：

```
raw/zones/        原始输入：导入的 zone 文本 + 规范化记录 + zone 指纹
raw/plans/        原始输入：分阶段计划、阻断校验结果、状态、决策、源计划引用
derived/simulations/  派生结果：节点、事件、逐探针证据、收敛（可复用的确定性产物）
derived/exports/      派生结果：完整证据导出包
events/requests.jsonl 追加、只增的操作事件日志（提交标记，含单调 seq）
events/requests/<request_id>.json  每个请求的幂等记录（响应、端点、载荷指纹）
tmp/              原子写临时目录，启动时清空（崩溃半成品不可见）
```

要点：

- **原始输入**（`raw/`）与**派生结果**（`derived/`）与**操作事件**（`events/`）物理分离。
- **Zone 指纹**：规范化记录行（小写名、TTL、类型、rdata）排序后的 SHA-256。
- **计划/参数/决策指纹**：对规范化 JSON 求 SHA-256；参数指纹包含显式 `seed` 与全部节点/延迟/网格配置。同一「计划指纹 + 参数指纹 + 决策指纹」重复模拟会复用同一 `simulation_id`（响应中 `"reused": true`），不会产生第二份业务结果。
- **复制计划**：副本是新 `plan_id`，带 `source_plan_id` 与源指纹；旧模拟在导出中仍回链旧指纹。
- 节点随机延迟由 `math/rand` 以 `seed` 派生：主流派生权威/递归节点的延迟与偏差，每个递归节点再以 `seed + (i+1)*7919` 派生独立选权威节点的随机流，保证可复现且节点间独立。
- 模拟使用固定逻辑纪元 `ReferenceEpoch=1700000000` 计算 RRSIG 窗口，结果不依赖运行机器的墙上时间。

### 模拟语义

- **阶段调度**：阶段顺序推进。阶段 `i` 的最早时刻 = 上一阶段实际决策时刻 + 本阶段 `min_observe_sec`；决策只能晚于不能早于该时刻。
- **权威传播**：阶段决策后，权威节点 `j` 在 `decision_at + delay_j` 才切换到新 zone；切换窗口内递归取到的版本取决于它选中的权威节点。
- **递归查询**：缓存命中（按本地含偏差时钟比较过期时间）直接返回并标记 `cache/negative_cache`；未命中则用本节点确定性随机流选一个权威，以「探针时刻 − 递归侧延迟」观察该权威的当前有效 zone，取回答案后按答案 TTL 写缓存。
- **负缓存 TTL**：NXDOMAIN/NODATA 使用 SOA `minimum`（RFC 2308 风格）。
- **回滚**：回滚事件把权威切回 base zone；收敛时间天然包含传播延迟与各节点此前缓存旧/新值的 TTL 尾巴。

### 发布前四项阻断（`publish_blocked`，计划仍会落盘为 `status=blocked`）

| code | 触发条件 |
| --- | --- |
| `cname_loop` | 跟随 CNAME 出现环，或链长超过 256 跳 |
| `broken_delegation` | 非顶点 NS 委派点没有 NS 目标，或 in-bailiwick NS 缺少 A/AAAA glue |
| `serial_rollback` | 相邻有效 zone 的 SOA 序列号按 RFC 1982 回退 |
| `signature_window_disjoint` | 相邻 zone 覆盖同一 rrset 的 RRSIG inception/expiration 窗口完全不相交 |

此外输入层面的非法操作（动作未知、删除顶点 SOA、SOA 字段非法等）返回 `invalid_input` / `invalid_operation`。

---

## 恢复与一致性保证

- **原子提交**：实体文档始终走 `tmp/` 临时文件 → `fsync` → `rename` → 目录 `fsync`。落盘中途崩溃时，目标位置要么是旧的完整文件，要么是新的完整文件，绝不会出现半成品。
- **启动清理**：重启时清空 `tmp/` 中残留临时文件；事件日志末尾被截断/损坏的半行视为未提交，扫描时忽略。
- **提交顺序**：先写实体文档，再追加事件日志（提交标记），最后写请求记录。重启时从 `events/requests/` 重建幂等索引、从 `raw/`、`derived/` 重建实体集合。
- **幂等**：每个写请求必须带 `request_id`。
  - 同 `request_id` + 同载荷：返回首次的同一响应，不产生第二份业务结果。
  - 同 `request_id` + 不同载荷：`409 state_conflict`。

---

## HTTP API 与错误分类

所有错误体统一为：

```json
{ "error": { "code": "...", "message": "...", "details": ... } }
```

| HTTP | code | 含义 |
| --- | --- | --- |
| 400 | `invalid_input` | JSON/字段格式、zone 解析错误（details 带行号） |
| 400 | `publish_blocked` | 四项安全阻断，details 为 block 列表 |
| 404 | `not_found` | 资源不存在 |
| 409 | `state_conflict` | 计划被阻断/已完成、阶段不匹配、违反最短观察时间、request_id 载荷冲突 |
| 500 | `internal_error` | 存储等内部故障 |

端点（写请求均需 `request_id`）：

- `POST /api/zones` 导入 current/candidate zone
- `GET  /api/zones`
- `POST /api/plans`（传 `plan.phases`，或传 `current_zone_id`+`candidate_zone_id` 自动 diff）
- `GET  /api/plans`
- `POST /api/plans/{id}/copy`
- `POST /api/plans/{id}/simulations`（body `parameters`，含 `seed`）
- `GET  /api/simulations/{id}`
- `POST /api/plans/{id}/phases/{index}/decision`（`action=proceed|rollback`，`at_sec`）
- `POST /api/simulations/{id}/export`
- `GET  /api/exports/{id}`
- `GET  /api/health`

### curl 示例

```bash
curl -s -X POST http://127.0.0.1:5205/api/zones -d '{
  "request_id":"z1","kind":"current","name":"example.test",
  "text":"$TTL 60\n@ IN SOA ns1.example.test. hostmaster 1 7200 3600 1209600 30\n@ IN NS ns1\nns1 IN A 10.0.0.1\nwww IN A 192.0.2.10\n"
}'
```

---

## 代码结构

```
cmd/server/         进程入口（--listen/--data）
internal/dns/       记录/zone 模型、RFC1035 风格解析器、权威解析、计划与四项校验
internal/sim/       时间推进引擎、节点延迟/偏差/缓存、探针、收敛、确定性指纹
internal/store/     原子写、追加事件日志、幂等请求、崩溃恢复
internal/service/   后端业务规则（关键判定所在）
internal/api/       HTTP 路由、错误分类、go:embed 浏览器界面
web/                浏览器界面源文件（构建时嵌入 internal/api/ui_static）
```

测试覆盖：解析（续行/相对名/TTL 后缀/通配符/错误行号）、四项阻断、CNAME/通配/负响应/RRSIG 窗口解析、引擎（同种子确定性、异种子差异、权威不同步、缓存与负缓存、回滚遵守 TTL）、存储（原子写、临时文件清理、幂等重放、三类分离）、HTTP 端到端（错误分类、阻断落盘、确定性复用、复制绑定旧指纹、决策冲突、回滚收敛、重启恢复）。
