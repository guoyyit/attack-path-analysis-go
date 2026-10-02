package attackpath

import (
	"math"
	"testing"
)

func approx(a, b float64) bool {
	return math.Abs(a-b) < 1e-12
}

func TestSmokeBasicChain(t *testing.T) {
	s := NewService()
	err := s.Apply([]Op{
		{Kind: OpUpsertAsset, Asset: &Asset{ID: "internet", External: true}},
		{Kind: OpUpsertAsset, Asset: &Asset{ID: "web", Critical: true}},
		{Kind: OpUpsertAsset, Asset: &Asset{ID: "db", Critical: true}},
		{Kind: OpUpsertRule, Rule: &ConnectivityRule{ID: "r1", From: "internet", To: "web"}},
		{Kind: OpUpsertRule, Rule: &ConnectivityRule{ID: "r2", From: "web", To: "db"}},
		{Kind: OpUpsertVuln, Vuln: &Vulnerability{ID: "v1", Asset: "web", Exploitability: 0.5}},
		{Kind: OpUpsertVuln, Vuln: &Vulnerability{ID: "v2", Asset: "db", Exploitability: 0.4}},
	})
	if err != nil {
		t.Fatalf("apply: %v", err)
	}

	if !s.Compromised("web") || !s.Compromised("db") {
		t.Fatalf("expected web and db compromised, got web=%v db=%v", s.Compromised("web"), s.Compromised("db"))
	}
	web := s.Risk("web")
	if web == nil || !approx(web.Score, 0.5) || web.PathCount != 1 {
		t.Fatalf("unexpected web risk: %+v", web)
	}
	db := s.Risk("db")
	if db == nil || !approx(db.Score, 0.2) || db.PathCount != 1 {
		t.Fatalf("unexpected db risk: %+v score=%v", db, db)
	}
	if !approx(db.Paths[0].Probability, 0.2) || len(db.Paths[0].Steps) != 2 {
		t.Fatalf("unexpected db path: %+v", db.Paths[0])
	}
}

func TestSmokePrecondition(t *testing.T) {
	s := NewService()
	_ = s.Apply([]Op{
		{Kind: OpUpsertAsset, Asset: &Asset{ID: "e", External: true}},
		{Kind: OpUpsertAsset, Asset: &Asset{ID: "h", Critical: true}},
		{Kind: OpUpsertRule, Rule: &ConnectivityRule{ID: "r", From: "e", To: "h", Capabilities: []string{"network"}}},
		{Kind: OpUpsertVuln, Vuln: &Vulnerability{ID: "v", Asset: "h", Exploitability: 0.9, Preconditions: []string{"ssh-key"}}},
	})
	if s.Compromised("h") {
		t.Fatalf("asset must not be reachable when precondition is unmet")
	}
	if s.Risk("h") != nil {
		t.Fatalf("expected no risk for unreachable asset")
	}
}
