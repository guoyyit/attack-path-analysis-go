# attack-path-analysis-go

本地攻击路径分析服务。输入资产清单（`Asset`）、连通/信任规则
（`ConnectRule`）与漏洞信息（`Vulnerability`），推导外部攻击者可攻陷的
资产集合、枚举到达关键资产的攻击路径，并给出可复现、与输入顺序无关的
风险结论。数据变化时仅重算受影响区域，结果与全量重建完全一致；查询在
并发更新下始终读取一致快照；状态持久化并可在崩溃后恢复。

## 模型

### 事实层

- `Asset`：`id` 唯一标识；`external` 表示直接暴露互联网；`critical`
  表示关键资产；`grants` 是攻陷该资产后获得的能力标签；`attrs` 为无序
  属性。
- `Vulnerability`：位于某个资产上，`exploitability∈[0,1]`；
  `protocol/port` 限定所需入站向量（空/0 为通配）；`requires` 是利用
  前置能力；`grants` 是利用成功后新增能力。
- `ConnectRule`：有向信任关系 `src -> dst`（协议/端口）。`src` 为
  `@internet` 时表示互联网入站可达。

### 派生攻击图

每条“连通规则 + 目标资产上协议端口匹配的漏洞”产生一条有向攻击边。
显式标记 `external` 但缺少入站规则的资产会补一条概率为 1 的合成边
（`@external-access`），保证可达性与路径枚举使用同一事实来源。边按
`(from,to,vulnID)` 排序、去重，确保确定性。

### 可达性定点（含环路终止）

从互联网入口出发做最小不动点迭代：仅当攻击者已持有某漏洞 `requires`
中的全部能力时才能沿边推进；攻陷目标后收集目标资产与该漏洞的
`grants`。新增能力会重新评估已达节点的出边。状态只在有限的资产/能力
集合上单调增长，因此**任意环路必然终止**并得到确定结果。

### 路径

路径为无环简单路径（DFS + 访问集合），每条步骤记录所用漏洞与其可利用
性。枚举同样校验前置条件：能力沿路径累积。默认枚举上限
`DefaultMaxSteps=12`，可用 `Constraint.MaxLength` 覆盖。

## 风险计算模型

- 单条路径风险为各步骤可利用性的乘积：
  `risk(path) = ∏ exploitability(step)`。
- 资产整体风险假设到达同一资产的不同路径为独立事件：
  `score = 1 - ∏(1 - risk(path_i))`。
  聚合前概率参与确定性排序，结果与输入顺序无关。
- 路径排序：风险降序；风险相同按节点序列字典序，再按步骤漏洞序列字典
  序，保证可复现。

以上独立性是建模假设（不同路径可能共享漏洞/资产，严格相关时该值为近
似上界），文档与代码中一致使用该定义。

## 更新语义（增量）

- 更新以 `ChangeSet` 为**原子批次**：同一批次内的 upsert/delete 要么
  全部生效，要么全部不生效。
- 批次先做校验（非空 ID、概率区间、引用完整性）。同一批次先应用
  upsert 再应用 delete（同一 ID 既增又删则最终删除）。
- 删除资产级联删除其漏洞与相关连通规则。
- 增量推导只重建与“脏资产”相关的边，其余边直接复用；影响区域取脏节点
  在**旧图与新图**上的前向闭包之并（保证删除边后旧可达节点被正确重
  估，可能变为不可达）；区域外的旧结论作为不动点种子保留。结果与全量
  重建逐字段一致（由随机化测试持续校验）。
- 每次成功提交产生一个单调递增的新版本快照。

## 并发与快照

`Service` 用互斥锁串行化更新，用不可变 `Snapshot` + 原子指针实现无锁
查询。读者拿到的快照在整个查询期间保持一致，绝不会读到部分更新的中间
状态。

## 持久化与崩溃恢复

持久化目录包含：

- `state.snap`：折叠后的全量快照（临时文件 + fsync + 原子 rename）。
- `wal.log`：追加式预写日志，每帧为
  `[8 字节载荷长度][4 字节 CRC32][JSON 载荷]`，提交前 fsync。

重放时先加载快照再顺序重放版本连续的 WAL 帧；长度不足或 CRC 不匹配的
尾部帧视为崩溃中未完成的写入，直接截断丢弃——**未提交不生效**。快照
定期压缩（每 64 帧），压缩后 WAL 仅保留快照基线之后的帧且保留原始全
局版本号，因此重放始终版本连续；压缩各阶段崩溃均可安全恢复。

## 查询接口

库接口（`attackpath.Service`）：

- `Open(dir string)`：`dir` 为空时纯内存。
- `Update(ChangeSet) error`：原子提交批次。
- `Current() *Snapshot`：当前一致快照。
- `Query(Constraint) QueryResult`：约束查询。
- `Report() *Report`：完整风险报告（入口、可达集合、每资产路径与聚
  合分）。

`Constraint` 字段：

- `starts`：起点集合，默认 `[@internet]`。
- `targets`：目标集合，默认全部 `critical` 资产。
- `required`：必经节点。
- `excluded`：排除节点。
- `max_length`：步骤数上限，0 使用默认值。

无解时返回 `QueryResult{Empty:true, Reason:...}` 明确说明原因（无关键
资产、节点不存在、约束/长度内无解等）。

HTTP 服务（`cmd/apasvc`，`APA_ADDR` / `APA_DATA` 配置）：

- `GET /health`
- `GET /snapshot`
- `GET /report`
- `POST /query`（请求体为 `Constraint` JSON）
- `POST /updates`（请求体为 `ChangeSet` JSON）

```bash
go run ./cmd/apasvc -addr 127.0.0.1:8080 -data ./data
curl -s localhost:8080/updates -d '{
  "upsert_assets": [
    {"id":"web","external":true,"grants":["shell"]},
    {"id":"db","critical":true}
  ],
  "upsert_vulns": [
    {"id":"v1","asset_id":"web","exploitability":0.7},
    {"id":"v2","asset_id":"db","exploitability":0.4,"requires":["shell"]}
  ],
  "upsert_rules": [
    {"src_id":"@internet","dst_id":"web"},
    {"src_id":"web","dst_id":"db"}
  ]
}'
curl -s localhost:8080/query -d '{}'
```

## 构建与测试

```bash
go build ./...
go vet ./...
go test ./...          # 功能、增量一致性、环路、约束、持久化
go test -race ./...    # 并发读写
```

测试覆盖：基础可达/前置条件、输入顺序无关、20 个随机种子×60 步的增量
与全量一致性、环路终止与确定性、必经/排除/长度/起点约束及空结果、
并发读写快照一致性、WAL 撕裂帧崩溃恢复、快照压缩与多次重开恢复、
HTTP 端到端。
