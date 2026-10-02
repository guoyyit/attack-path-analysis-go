package attackpath

import (
	"testing"
	"time"
)

func ringBatch() ChangeSet {
	cs := ChangeSet{
		UpsertAssets: []Asset{
			{ID: "x0", External: true, Grants: []string{"k"}},
			{ID: "x1", Grants: []string{"k"}},
			{ID: "x2", Grants: []string{"k"}},
			{ID: "x3", Critical: true, Grants: []string{"k"}},
		},
		UpsertVulns: []Vulnerability{
			{ID: "vx0", AssetID: "x0", Exploitability: 0.9},
			{ID: "vx1", AssetID: "x1", Exploitability: 0.9, Requires: []string{"k"}},
			{ID: "vx2", AssetID: "x2", Exploitability: 0.9, Requires: []string{"k"}},
			{ID: "vx3", AssetID: "x3", Exploitability: 0.9, Requires: []string{"k"}},
		},
		UpsertRules: []ConnectRule{
			{SrcID: InternetID, DstID: "x0"},
			{SrcID: "x0", DstID: "x1"},
			{SrcID: "x1", DstID: "x2"},
			{SrcID: "x2", DstID: "x3"},
			// Cycle edges in both directions.
			{SrcID: "x3", DstID: "x2"},
			{SrcID: "x2", DstID: "x1"},
			{SrcID: "x1", DstID: "x0"},
			{SrcID: "x3", DstID: "x0"},
			{SrcID: "x0", DstID: "x3"},
		},
	}
	return cs
}

func TestCycleTerminates(t *testing.T) {
	svc := testService(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := svc.Update(ringBatch()); err != nil {
			t.Errorf("update: %v", err)
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("fixed point did not terminate on cyclic graph")
	}

	snap := svc.Current()
	for _, id := range []string{"x0", "x1", "x2", "x3"} {
		if !snap.reached[id] {
			t.Fatalf("node %s should be reachable", id)
		}
	}
	res := svc.Query(Constraint{})
	if res.Empty {
		t.Fatalf("expected paths despite cycle")
	}
	for _, p := range res.Paths {
		if !allUnique(p.Nodes) {
			t.Fatalf("enumerated path revisits a node: %v", p.Nodes)
		}
	}
	// Determinism: rebuilding yields identical paths.
	res2 := svc.Query(Constraint{})
	if len(res.Paths) != len(res2.Paths) {
		t.Fatalf("non deterministic path count")
	}
	for i := range res.Paths {
		if !equalStrings(res.Paths[i].Nodes, res2.Paths[i].Nodes) {
			t.Fatalf("non deterministic ordering")
		}
	}
}

func TestConstrainedQueries(t *testing.T) {
	svc := testService(t)
	mustUpdate(t, svc, diamondBatch())

	// Required node.
	res := svc.Query(Constraint{Required: []string{"mid2"}})
	if res.Empty {
		t.Fatalf("expected a path through mid2")
	}
	for _, p := range res.Paths {
		if !containsID(p.Nodes, "mid2") {
			t.Fatalf("path does not include required mid2: %v", p.Nodes)
		}
	}

	// Excluded node removes one branch.
	resEx := svc.Query(Constraint{Excluded: []string{"mid1"}})
	if resEx.Empty {
		t.Fatalf("mid2 branch should remain after excluding mid1")
	}
	for _, p := range resEx.Paths {
		if containsID(p.Nodes, "mid1") {
			t.Fatalf("excluded mid1 appeared in path: %v", p.Nodes)
		}
	}

	// Excluding every intermediary yields an explicit empty result.
	resNone := svc.Query(Constraint{Excluded: []string{"mid1", "mid2"}})
	if !resNone.Empty || resNone.Reason == "" {
		t.Fatalf("expected explicit empty result, got %+v", resNone)
	}

	// MaxLength 1 hop cannot reach crown (two hops away).
	resShort := svc.Query(Constraint{MaxLength: 1})
	if !resShort.Empty {
		t.Fatalf("no 1-hop path expected, got %d", len(resShort.Paths))
	}

	// Custom start set: only mid2 can reach crown in one hop.
	resStart := svc.Query(Constraint{Starts: []string{"mid2"}})
	if resStart.Empty {
		t.Fatalf("mid2 should reach crown")
	}
	for _, p := range resStart.Paths {
		if p.Nodes[0] != "mid2" {
			t.Fatalf("path must start at mid2, got %v", p.Nodes)
		}
	}

	// Unknown nodes are reported explicitly.
	resBad := svc.Query(Constraint{Required: []string{"ghost"}})
	if !resBad.Empty {
		t.Fatalf("unknown required node must produce empty result")
	}

	// Sorted by descending risk.
	resAll := svc.Query(Constraint{})
	for i := 1; i < len(resAll.Paths); i++ {
		if resAll.Paths[i-1].Risk < resAll.Paths[i].Risk {
			t.Fatalf("paths not sorted by descending risk")
		}
	}
}

// diamondBatch creates internet -> {mid1 (0.2), mid2 (0.9)} -> crown.
func diamondBatch() ChangeSet {
	return ChangeSet{
		UpsertAssets: []Asset{
			{ID: "entry", External: true, Grants: []string{"k"}},
			{ID: "mid1", Grants: []string{"k"}},
			{ID: "mid2", Grants: []string{"k"}},
			{ID: "crown", Critical: true},
		},
		UpsertVulns: []Vulnerability{
			{ID: "ve", AssetID: "entry", Exploitability: 1},
			{ID: "vm1", AssetID: "mid1", Exploitability: 0.2, Requires: []string{"k"}},
			{ID: "vm2", AssetID: "mid2", Exploitability: 0.9, Requires: []string{"k"}},
			{ID: "vc1", AssetID: "crown", Exploitability: 1, Requires: []string{"k"}},
			{ID: "vc2", AssetID: "crown", Exploitability: 1, Requires: []string{"k"}},
		},
		UpsertRules: []ConnectRule{
			{SrcID: InternetID, DstID: "entry"},
			{SrcID: "entry", DstID: "mid1"},
			{SrcID: "entry", DstID: "mid2"},
			{SrcID: "mid1", DstID: "crown"},
			{SrcID: "mid2", DstID: "crown"},
		},
	}
}

func mustUpdate(t *testing.T, svc *Service, cs ChangeSet) {
	t.Helper()
	if err := svc.Update(cs); err != nil {
		t.Fatal(err)
	}
}

func allUnique(nodes []string) bool {
	seen := map[string]bool{}
	for _, n := range nodes {
		if seen[n] {
			return false
		}
		seen[n] = true
	}
	return true
}

func containsID(nodes []string, id string) bool {
	for _, n := range nodes {
		if n == id {
			return true
		}
	}
	return false
}
