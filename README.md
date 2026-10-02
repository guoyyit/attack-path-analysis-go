# attack-path-analysis-go

本地攻击路径分析服务：输入资产清单、连通规则（信任关系）与漏洞信息，从外部
入口逐步推导可被攻陷的资产，枚举到达关键资产的攻击路径并计算风险。支持
增量更新、带约束查询、并发读写的快照一致性，以及基于预写日志的持久化与
崩溃恢复。

## 特性

- 图模型：资产 + 有向连通规则 + 漏洞利用前置条件（规则能力 ⊇ 漏洞前置）。
- 确定性不动点推导攻陷集合，存在环路必然终止；路径枚举只产出无环简单路径。
- 风险：路径概率为各步利用概率之积；资产风险按多路径独立的 noisy-OR
  `1 - Π(1 - P(path))` 聚合，结果可复现、与输入顺序无关。
- 增量更新只重算受影响的前向闭包区域，随机差分测试证明与全量重建完全一致。
- 查询支持起点集合、必经节点、排除节点、路径长度上限，按风险排序，无解
  返回 `[]`。
- 不可变快照 + `atomic.Pointer`，并发查询永不读到部分更新。
- 校验和、fsync 的预写日志：重启恢复全部已提交数据，崩溃残帧（未完成提交）
  被截断不生效。

## 快速开始

```bash
go run ./cmd/server -addr :8080 -data ./data
```

```bash
curl -s localhost:8080/apply -d '{
  "ops":[
    {"kind":"upsert_asset","asset":{"id":"internet","external":true}},
    {"kind":"upsert_asset","asset":{"id":"db","critical":true}},
    {"kind":"upsert_rule","rule":{"id":"r1","from":"internet","to":"db"}},
    {"kind":"upsert_vuln","vuln":{"id":"v1","asset":"db","exploitability":0.5}}
  ]}'

curl -s localhost:8080/query -d '{"target":"db"}'
curl -s localhost:8080/risk/db
```

## 作为库使用

```go
import attackpath "github.com/guoyyit/attack-path-analysis-go"

s, _ := attackpath.Open("./data")          // 持久化；NewService() 为纯内存
defer s.Close()

_ = s.Apply([]attackpath.Op{
    {Kind: attackpath.OpUpsertAsset, Asset: &attackpath.Asset{ID: "e", External: true}},
    {Kind: attackpath.OpUpsertAsset, Asset: &attackpath.Asset{ID: "k", Critical: true}},
    {Kind: attackpath.OpUpsertRule, Rule: &attackpath.ConnectivityRule{ID: "r", From: "e", To: "k"}},
    {Kind: attackpath.OpUpsertVuln, Vuln: &attackpath.Vulnerability{ID: "v", Asset: "k", Exploitability: 0.5}},
})

results := s.Query(attackpath.Query{
    Target: "k",
    Constraint: attackpath.Constraint{MaxSteps: 5, MustInclude: []string{}, Exclude: []string{}},
})
_ = s.Compromised("k")
_ = s.Risk("k")
```

## 测试

```bash
go test -race -count=1 ./...
```

## 文档

风险计算模型、增量更新语义、查询/HTTP 接口与恢复机制详见
[docs/design.md](docs/design.md)。
