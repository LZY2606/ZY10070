# DNS 区域发布模拟器（zonesim）

在真正改动区域文件之前，模拟 **TTL 到期**、**多台权威服务器不同步**、
**递归缓存残留（含负缓存）**、**CNAME 链/通配符/委派** 与 **DNSSEC 签名窗口**
共同作用的后果。发布被建模为多个阶段（每阶段只能改指定记录、并要求最短观察
时间），页面可以拖动时间，查看每个递归节点在同一时刻看到的答案，并计算所有
节点收敛到最终答案的最早时刻。

所有关键判定（解析、阻断校验、时间推进、收敛）都在服务端完成；浏览器只是
客户端。模拟结果完全确定，节点的随机延迟只来自显式种子。

## 安装与运行

仅依赖 Go 标准库（Go 1.26+）。

```bash
go mod download
go test ./... -count=1
go run ./cmd/server --listen 127.0.0.1:5205
```

打开固定页面：<http://127.0.0.1:5205>

数据目录默认是系统临时目录下的 `zonesim-data`，可用 `--data` 或环境变量
`ZONESIM_DATA` 覆盖。再次运行同一路径会恢复全部文档与事件。

## 30 秒演示

1. 启动后点击右上角 **“载入演示数据”**。系统导入：
   - 一个正常的 `current → candidate`（`www` 换地址、新增 `shop`、删除 `old`、
     SOA 序列号递增），生成两阶段计划；
   - 一个**必然被阻断**的候选（SOA 序列号回退 + `loop1/loop2` CNAME 环）。
2. 在“已有计划”里选中原计划，点击 **提交前校验**，看到两个阶段都 `accepted`；
   选中被阻断的计划，能看到 `CNAME_LOOP`、`SERIAL_ROLLBACK` 等 blocker，
   点 **提交发布** 会被服务端拒绝（HTTP 409）。
3. 对正常计划点 **提交发布**，再到“确定性模拟”里设置种子/探测查询，点
   **运行模拟**。右侧出现各节点卡片与时间轴，可拖动滑块。
4. 观察同一次查询的标签在 **权威答案 / 缓存命中 / 负缓存** 之间切换；
   顶部给出“最早全员收敛”的时刻。删除 `old` 后，缓存里先出现 `negative_cache`，
   TTL 到期后才向权威重新确认。
5. 把“回滚时刻”设为正数重新运行：新地址即使在权威侧已撤回，也要等已经发出的
   TTL 到期，节点才会重新看到旧地址——不会出现“旧记录瞬间回来”。
6. 点 **复制并改阶段** 修改阶段再模拟：旧模拟仍绑定旧的 zone/计划指纹，
   不会被错误复用；同一份候选与相同参数重复模拟则直接复用确定性结果
   （响应带 `reused: true` 与 `X-Simulation-Reused: true`）。
7. 点 **导出完整证据**，得到包含 zone 原文、完整查询时间线、阶段决策与操作
   事件的 JSON。

## 数据模型（三类存储严格分离）

```
<data-dir>/
  raw/zones/                 # 原始输入：导入的 zone 原文与指纹
  derived/plans/             # 派生：计划、diff、校验、决策
  derived/simulations/       # 派生：确定性模拟报告（完整查询证据）
  derived/exports/           # 派生：导出包、即时查询副日志
  events/journal.jsonl       # 操作事件（append-only，带单调序号）
  requests/                  # X-Request-Id 幂等台账
  tmp/                       # 原子写临时文件，重启即清理
  lock                       # flock，禁止两个进程共用同一数据目录
```

- **原始输入**：`ZoneDoc{id,label,origin,text,fingerprint}`。指纹是
  origin + 规范化排序后记录集的 SHA-256，相同候选内容指纹一致。
- **派生结果**：
  - `Plan`：RRset 级 diff、阶段列表、校验 findings、每阶段 `PhaseDecision`、
    状态机（`draft → ready/committed → rolled_back`）、`revision` 与
    `base_plan_id`。
  - `Simulation`：`Config` + 身份哈希 `identity` + `Report`。身份哈希覆盖
    两个 zone 指纹、种子、节点（含时钟偏差）、探测、延迟上界、查询间隔、
    horizon、回滚时刻和全部阶段。修改任何一项都会产生新身份。
  - 报告按 `节点 × 查询` 存半开区间时间线，每段带来源标签、状态、DNSSEC
    安全状态、TTL 与记录集，并给出每个查询以及全局的最早收敛时刻。
- **操作事件**：`zone.imported / plan.created / plan.validated /
  plan.committed / plan.rollback_initiated / simulation.created /
  simulation.adhoc_query / simulation.exported` 等，只追加、带序号，
  与业务文档分开存放。

## 模拟语义

- **时间**：模拟秒 0 锚定为固定纪元 `2026-01-01T00:00:00Z`，页面同时展示对应
  UTC 墙钟时间，便于解释 RRSIG 的 inception/expiration。
- **权威不同步**：每个阶段在其累计最短观察时间之后“计划生效”；每台权威服务
  器对每个 RRset 的同步延迟由 `(seed, 方向, 服务器, key)` 的确定性 LCG 产生，
  范围 1..`max_delay_seconds`。回滚方向的延迟独立派生。
- **递归节点**：每个节点有显式时钟偏差（秒）、由种子哈希稳定选出的首选权威
  服务器，以及独立缓存。缓存未命中才向权威取数；正响应按 RRset TTL 缓存，
  负响应按 SOA minimum（演示 zone 为 300 秒）缓存。
- **答案来源**：`authority`（当次向权威取数）、`cache`（正缓存命中）、
  `negative_cache`（NXDOMAIN/NODATA 负缓存命中）。
- **DNSSEC**：解析时挂上覆盖该 RRset 的 RRSIG；在**节点自己的时钟**下，
  窗口内任一签名有效即 `secure`，应签但当前视图无有效签名为 `bogus`，
  无签名为 `insecure`。时钟偏差因此会让不同节点在签名边界上看到不同结果。
- **解析**：支持最长后缀通配符（且不跨越委派切点）、CNAME 链迭代跟随、
  CNAME 环 → SERVFAIL、非 apex NS 切点 → REFERRAL（查询切点本身的 NS 仍为
  权威答案）、NODATA 与 NXDOMAIN（区分依据是最近父节点是否存在）。
- **收敛**：以所有权威服务器的最后变更时刻为下界，从时间线尾部回溯，取每个
  节点持续保持最终答案的最早查询时刻；所有节点最终答案一致且都在 horizon 内
  才算收敛，全局收敛时刻取所有查询的最大值。
- **回滚**：在 `rollback_at_seconds` 后安排一次独立延迟的“撤回”事件；节点
  继续按既有 TTL 提供新数据，直到缓存失效才重新取到旧数据。回滚报告与主
  报告使用同一确定性调度。

## 提交前阻断项

`internal/dns/validate.go` 在创建/校验/提交时（提交时再次强制运行）检查：

- `CNAME_LOOP`：CNAME 链在区内闭合成环；`CNAME_COEXISTS`：CNAME 与其它数据
  同名共存。
- `BROKEN_DELEGATION`：非 apex NS 委派指向区内不存在、或没有 A/AAAA glue 的
  名字服务器。
- `SERIAL_ROLLBACK`：候选 SOA 序列号按 RFC 1982 不大于当前序列号。
- `SIGNATURE_WINDOW_DISJOINT`：同一已存在 RRset 的新旧 RRSIG 有效窗口完全
  不相交，字段验证期间没有重叠窗口可用。

只有不存在 blocker 时计划才能进入 `committed`。阶段还必须满足：每个阶段只能
引用当前→候选 diff 中真实存在的 key，并且每个变化 key 都必须被某个阶段覆盖。

## 持久化、幂等与崩溃恢复

- 所有文档写入都是 **临时文件 → fsync → rename → fsync 目录**，进程在落盘
  中途退出，重启后绝不会读到半成品；`tmp/` 中的残留文件在启动时清理。
- 变更类请求接受 `X-Request-Id` 头：首次请求先写 `claimed` 台账，业务结果
  落盘后改写为 `done{result_id}`；同一 request id 重放直接返回**原始结果**，
  不会产生第二份业务结果（例如不会出现第二份 zone/计划/模拟）。
- 若进程在 `claimed` 之后、结果落盘之前崩溃，重启恢复会发现结果文档不存在并
  删除该台账，允许客户端用同一个 request id 安全重试一次。
- 数据目录用 `flock` 排他锁定，防止两个进程同时写同一目录。
- 事件日志每行一个 JSON、带全局单调序号，重启后续号从日志最大值继续。

## HTTP API 摘要

| 方法 路径 | 说明 |
| --- | --- |
| `POST /api/zones` | 导入 zone（原始输入），支持 `X-Request-Id` |
| `GET /api/zones` / `GET /api/zones/{id}` | 列表 / 详情 |
| `POST /api/plans` | 生成分阶段计划（diff + 阻断校验） |
| `PUT /api/plans/{id}` | 修改 draft 阶段（乐观锁 `revision`） |
| `POST /api/plans/{id}/copy` | 复制计划以便改阶段 |
| `POST /api/plans/{id}/validate` | 重跑校验并落每阶段决策 |
| `POST /api/plans/{id}/commit` | 无 blocker 才允许提交 |
| `POST /api/plans/{id}/rollback` | 发起回滚（状态机约束） |
| `POST /api/simulations` | 运行/复用确定性模拟 |
| `POST /api/simulations/{id}/view` | 时间滑块：某时刻某查询的逐节点视图 |
| `POST /api/simulations/{id}/adhoc` | 记录一次操作者即时查询（不改确定性报告） |
| `GET  /api/simulations/{id}/export` | 完整证据 + 阶段决策 + 事件 |
| `GET  /api/events` | 操作事件日志 |
| `POST /api/demo/load` | 一键播种演示数据 |

错误响应统一为 `application/json`，结构为
`{"error":{"class","code","message"}}`，`class` 明确区分：

- `invalid_request`（HTTP 400）：zone 解析失败、阶段非法、模拟配置非法、
  JSON 无法解析等；
- `state_conflict`（HTTP 409）：提交带 blocker 的计划、编辑/重复提交/回滚
  状态不对、乐观锁 revision 冲突等；
- `not_found`（HTTP 404）；
- `internal_error`（HTTP 500）：落盘或存储故障。

## 代码布局

```
cmd/server             进程入口（--listen / --data）
internal/dns           zone 模型、解析器、解析视图、diff 与发布前校验
internal/sim           确定性引擎：权威时间线、节点缓存、收敛、身份哈希
internal/store         原子存储、事件日志、幂等台账、崩溃恢复、flock
internal/service      领域编排（关键判定都在这里）
internal/api           HTTP/JSON 与嵌入的浏览器界面
internal/api/web       index.html + app.js（无构建步骤、无外部依赖）
```

## 说明与边界

这是一个用于发布推演的模拟器，不做真实网络收发包，也不做 RRSIG 密码学验证
（按签名时间窗模拟 `secure/bogus/insecure`）；单 zone 视角，出区的 CNAME 在
链末端停止，出区委派返回 REFERRAL。查询网格按固定步长（`query_every_seconds`）
推进，因此收敛时刻以该步长为分辨率。
