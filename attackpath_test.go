package attackpath

import (
	"math"
	"testing"
)

func testService(t *testing.T) *Service {
	t.Helper()
	svc, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = svc.Close() })
	return svc
}

func baseBatch() ChangeSet {
	return ChangeSet{
		UpsertAssets: []Asset{
			{ID: "web", External: true, Critical: false},
			{ID: "app"},
			{ID: "db", Critical: true},
		},
		UpsertVulns: []Vulnerability{
			{ID: "cve-web", AssetID: "web", Exploitability: 0.8},
			{ID: "cve-app", AssetID: "app", Exploitability: 0.5, Requires: []string{"web-shell"}},
			{ID: "cve-db", AssetID: "db", Exploitability: 0.25, Requires: []string{"app-creds"}},
		},
		UpsertRules: []ConnectRule{
			{SrcID: InternetID, DstID: "web", Protocol: "tcp", Port: 443},
			{SrcID: "web", DstID: "app", Protocol: "tcp", Port: 8080},
			{SrcID: "app", DstID: "db", Protocol: "tcp", Port: 5432},
		},
	}
}

// web-shell is granted after owning web; app-creds after owning app.
func capabilityBatch() ChangeSet {
	return ChangeSet{
		UpsertAssets: []Asset{
			{ID: "web", External: true, Grants: []string{"web-shell"}},
			{ID: "app", Grants: []string{"app-creds"}},
			{ID: "db", Critical: true},
		},
	}
}

func TestBasicReachabilityAndPath(t *testing.T) {
	svc := testService(t)
	if err := svc.Update(baseBatch()); err != nil {
		t.Fatalf("update: %v", err)
	}
	if err := svc.Update(capabilityBatch()); err != nil {
		t.Fatalf("update caps: %v", err)
	}

	snap := svc.Current()
	if !equalStringSets(snap.entries, []string{"web"}) {
		t.Fatalf("entries = %v, want [web]", snap.entries)
	}
	if !snap.reached["db"] {
		t.Fatalf("db must be reachable via chained exploitation")
	}

	res := svc.Query(Constraint{})
	if res.Empty {
		t.Fatalf("expected paths to critical db, got empty: %s", res.Reason)
	}
	if len(res.Paths) != 1 {
		t.Fatalf("want 1 path, got %d", len(res.Paths))
	}
	p := res.Paths[0]
	wantNodes := []string{InternetID, "web", "app", "db"}
	if !equalStrings(p.Nodes, wantNodes) {
		t.Fatalf("nodes = %v, want %v", p.Nodes, wantNodes)
	}
	wantRisk := 0.8 * 0.5 * 0.25
	if math.Abs(p.Risk-wantRisk) > 1e-12 {
		t.Fatalf("risk = %.4f, want %.4f", p.Risk, wantRisk)
	}
	rep := svc.Report()
	if math.Abs(rep.Risks["db"].Score-wantRisk) > 1e-12 {
		t.Fatalf("db score = %.4f, want %.4f", rep.Risks["db"].Score, wantRisk)
	}
	if rep.Risks["db"] == nil || !rep.Risks["db"].Reachable {
		t.Fatalf("db risk record missing")
	}
}

func TestPreconditionBlocksReach(t *testing.T) {
	svc := testService(t)
	if err := svc.Update(baseBatch()); err != nil {
		t.Fatalf("update: %v", err)
	}
	// No capabilities granted anywhere: app cannot be exploited.
	snap := svc.Current()
	if snap.reached["app"] {
		t.Fatalf("app must not be reachable without web-shell capability")
	}
	if snap.reached["db"] {
		t.Fatalf("db must not be reachable")
	}
	res := svc.Query(Constraint{})
	if !res.Empty {
		t.Fatalf("expected empty result, got %d paths", len(res.Paths))
	}
	if res.Reason == "" {
		t.Fatalf("empty result must explain why")
	}
}

func TestInputOrderIndependence(t *testing.T) {
	build := func(swap bool) *Report {
		svc := testService(t)
		b := baseBatch()
		c := capabilityBatch()
		if swap {
			b.UpsertAssets = reverseAssets(b.UpsertAssets)
			b.UpsertVulns = reverseVulns(b.UpsertVulns)
			b.UpsertRules = reverseRules(b.UpsertRules)
		}
		if err := svc.Update(b); err != nil {
			t.Fatal(err)
		}
		if err := svc.Update(c); err != nil {
			t.Fatal(err)
		}
		return svc.Report()
	}
	a := build(false)
	b := build(true)
	if !reportsEqual(a, b) {
		t.Fatalf("reports differ by input order:\n%#v\n%#v", a, b)
	}
}

func equalStringSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	set := map[string]int{}
	for _, s := range a {
		set[s]++
	}
	for _, s := range b {
		set[s]--
		if set[s] < 0 {
			return false
		}
	}
	return true
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func reverseAssets(in []Asset) []Asset {
	out := make([]Asset, len(in))
	for i := range in {
		out[len(in)-1-i] = in[i]
	}
	return out
}

func reverseVulns(in []Vulnerability) []Vulnerability {
	out := make([]Vulnerability, len(in))
	for i := range in {
		out[len(in)-1-i] = in[i]
	}
	return out
}

func reverseRules(in []ConnectRule) []ConnectRule {
	out := make([]ConnectRule, len(in))
	for i := range in {
		out[len(in)-1-i] = in[i]
	}
	return out
}

func reportsEqual(a, b *Report) bool {
	if !equalStrings(a.Entries, b.Entries) || !equalStrings(a.Reachable, b.Reachable) {
		return false
	}
	if len(a.Risks) != len(b.Risks) {
		return false
	}
	for id, ra := range a.Risks {
		rb, ok := b.Risks[id]
		if !ok || rb.Reachable != ra.Reachable {
			return false
		}
		if math.Abs(ra.Score-rb.Score) > 1e-12 || len(ra.Paths) != len(rb.Paths) {
			return false
		}
		for i := range ra.Paths {
			if !equalStrings(ra.Paths[i].Nodes, rb.Paths[i].Nodes) ||
				math.Abs(ra.Paths[i].Risk-rb.Paths[i].Risk) > 1e-12 {
				return false
			}
		}
	}
	return true
}
