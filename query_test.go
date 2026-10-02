package attackpath

import "testing"

func buildCycleService(t *testing.T) *Service {
	t.Helper()
	s := NewService()
	ops := []Op{
		{Kind: OpUpsertAsset, Asset: &Asset{ID: "e", External: true}},
		{Kind: OpUpsertAsset, Asset: &Asset{ID: "a"}},
		{Kind: OpUpsertAsset, Asset: &Asset{ID: "b"}},
		{Kind: OpUpsertAsset, Asset: &Asset{ID: "c"}},
		{Kind: OpUpsertAsset, Asset: &Asset{ID: "k", Critical: true}},
		// Two fully cyclic triangles plus a chain into the key asset.
		{Kind: OpUpsertRule, Rule: &ConnectivityRule{ID: "ea", From: "e", To: "a"}},
		{Kind: OpUpsertRule, Rule: &ConnectivityRule{ID: "ab", From: "a", To: "b"}},
		{Kind: OpUpsertRule, Rule: &ConnectivityRule{ID: "ba", From: "b", To: "a"}},
		{Kind: OpUpsertRule, Rule: &ConnectivityRule{ID: "bc", From: "b", To: "c"}},
		{Kind: OpUpsertRule, Rule: &ConnectivityRule{ID: "cb", From: "c", To: "b"}},
		{Kind: OpUpsertRule, Rule: &ConnectivityRule{ID: "ck", From: "c", To: "k"}},
		{Kind: OpUpsertVuln, Vuln: &Vulnerability{ID: "va", Asset: "a", Exploitability: 0.8}},
		{Kind: OpUpsertVuln, Vuln: &Vulnerability{ID: "vb", Asset: "b", Exploitability: 0.5}},
		{Kind: OpUpsertVuln, Vuln: &Vulnerability{ID: "vc", Asset: "c", Exploitability: 0.5}},
		{Kind: OpUpsertVuln, Vuln: &Vulnerability{ID: "vk", Asset: "k", Exploitability: 0.25}},
	}
	if err := s.Apply(ops); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestCycleTerminatesWithDeterministicSimplePaths(t *testing.T) {
	s := buildCycleService(t)

	risks := s.Query(Query{Target: "k"})
	if len(risks) != 1 {
		t.Fatalf("expected one risk row, got %d", len(risks))
	}
	r := risks[0]
	// Only one simple route e->a->b->c->k despite the cycles a<->b, b<->c.
	if r.PathCount != 1 {
		t.Fatalf("expected exactly one simple path, got %d: %+v", r.PathCount, r.Paths)
	}
	if !approx(r.Score, 0.8*0.5*0.5*0.25) {
		t.Fatalf("unexpected path score: %v", r.Score)
	}

	// Repeatability: queries are deterministic.
	r2 := s.Query(Query{Target: "k"})
	if !approx(r2[0].Score, r.Score) || r2[0].PathCount != r.PathCount {
		t.Fatalf("query is not reproducible")
	}
}

func TestConstraintMaxSteps(t *testing.T) {
	s := buildCycleService(t)

	// Target is four hops away.
	if got := s.Query(Query{Target: "k", Constraint: Constraint{MaxSteps: 3}}); len(got) != 0 {
		t.Fatalf("expected empty result with 3-step cap, got %d", len(got))
	}
	got := s.Query(Query{Target: "k", Constraint: Constraint{MaxSteps: 4}})
	if len(got) != 1 || got[0].PathCount != 1 {
		t.Fatalf("expected the path with a 4-step cap, got %+v", got)
	}
}

func TestConstraintExclude(t *testing.T) {
	s := buildCycleService(t)

	got := s.Query(Query{Target: "k", Constraint: Constraint{Exclude: []string{"b"}}})
	if len(got) != 0 {
		t.Fatalf("expected empty result when the only route is excluded")
	}
}

func TestConstraintMustInclude(t *testing.T) {
	s := buildCycleService(t)

	got := s.Query(Query{Target: "k", Constraint: Constraint{MustInclude: []string{"a", "c"}}})
	if len(got) != 1 || got[0].PathCount != 1 {
		t.Fatalf("expected path through a and c, got %+v", got)
	}
	if got2 := s.Query(Query{Target: "k", Constraint: Constraint{MustInclude: []string{"zzz"}}}); len(got2) != 0 {
		t.Fatalf("must-include an absent node must yield empty result")
	}
}

func TestConstraintStartSet(t *testing.T) {
	s := buildCycleService(t)

	// Starting at an internal node still reaches k.
	got := s.Query(Query{Target: "k", Constraint: Constraint{StartAssets: []string{"b"}}})
	if len(got) != 1 || got[0].Paths[0].Start != "b" {
		t.Fatalf("expected b->...->k path, got %+v", got)
	}
	// A disconnected start yields an explicit empty result.
	empty := s.Query(Query{Target: "k", Constraint: Constraint{StartAssets: []string{"e"}, Exclude: []string{"a"}}})
	if empty != nil && len(empty) != 0 {
		t.Fatalf("expected empty slice, got %+v", empty)
	}
}

func TestQueryCriticalDefaultAndSorting(t *testing.T) {
	s := NewService()
	ops := []Op{
		{Kind: OpUpsertAsset, Asset: &Asset{ID: "e", External: true}},
		{Kind: OpUpsertAsset, Asset: &Asset{ID: "low", Critical: true}},
		{Kind: OpUpsertAsset, Asset: &Asset{ID: "high", Critical: true}},
		{Kind: OpUpsertRule, Rule: &ConnectivityRule{ID: "rl", From: "e", To: "low"}},
		{Kind: OpUpsertRule, Rule: &ConnectivityRule{ID: "rh", From: "e", To: "high"}},
		{Kind: OpUpsertVuln, Vuln: &Vulnerability{ID: "vl", Asset: "low", Exploitability: 0.1}},
		{Kind: OpUpsertVuln, Vuln: &Vulnerability{ID: "vh", Asset: "high", Exploitability: 0.9}},
	}
	if err := s.Apply(ops); err != nil {
		t.Fatal(err)
	}
	got := s.Query(Query{})
	if len(got) != 2 || got[0].AssetID != "high" || got[1].AssetID != "low" {
		t.Fatalf("expected critical assets sorted by descending risk, got %+v", got)
	}
}

func TestMultiPathAggregation(t *testing.T) {
	s := NewService()
	ops := []Op{
		{Kind: OpUpsertAsset, Asset: &Asset{ID: "e", External: true}},
		{Kind: OpUpsertAsset, Asset: &Asset{ID: "k", Critical: true}},
		{Kind: OpUpsertRule, Rule: &ConnectivityRule{ID: "r1", From: "e", To: "k"}},
		{Kind: OpUpsertVuln, Vuln: &Vulnerability{ID: "v1", Asset: "k", Exploitability: 0.5}},
		{Kind: OpUpsertVuln, Vuln: &Vulnerability{ID: "v2", Asset: "k", Exploitability: 0.5}},
	}
	if err := s.Apply(ops); err != nil {
		t.Fatal(err)
	}
	r := s.Risk("k")
	// Two distinct single-step paths at 0.5 each: 1 - 0.5*0.5 = 0.75.
	if r.PathCount != 2 || !approx(r.Score, 0.75) {
		t.Fatalf("expected 2 paths aggregated to 0.75, got %+v", r)
	}
}
