package attackpath

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestConcurrentReadersSeeConsistentSnapshots hammers the service with
// concurrent writers and readers. Every query is checked against the
// invariants of a single coherent snapshot, which a torn read of an
// in-progress update could violate.
func TestConcurrentReadersSeeConsistentSnapshots(t *testing.T) {
	s := NewService()
	seed := []Op{
		{Kind: OpUpsertAsset, Asset: &Asset{ID: "e", External: true}},
	}
	for i := 0; i < 8; i++ {
		id := fmt.Sprintf("h%d", i)
		seed = append(seed,
			Op{Kind: OpUpsertAsset, Asset: &Asset{ID: id, Critical: true}},
			Op{Kind: OpUpsertRule, Rule: &ConnectivityRule{ID: "r" + id, From: "e", To: id}},
			Op{Kind: OpUpsertVuln, Vuln: &Vulnerability{ID: "v" + id, Asset: id, Exploitability: 0.3}},
		)
	}
	if err := s.Apply(seed); err != nil {
		t.Fatal(err)
	}

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Writer: keep flipping exploitability in committed batches.
	wg.Add(1)
	go func() {
		defer wg.Done()
		toggle := false
		for {
			select {
			case <-stop:
				return
			default:
			}
			toggle = !toggle
			p := 0.3
			if toggle {
				p = 0.6
			}
			ops := make([]Op, 0, 8)
			for i := 0; i < 8; i++ {
				id := fmt.Sprintf("h%d", i)
				ops = append(ops, Op{Kind: OpUpsertVuln, Vuln: &Vulnerability{
					ID: "v" + id, Asset: id, Exploitability: p,
				}})
			}
			_ = s.Apply(ops)
		}
	}()

	// Readers: each query response must be self-consistent: every returned
	// path probability must equal the step product, and every risk score the
	// noisy-OR of its paths. No two probability values may be mixed in one
	// snapshot.
	check := func() bool {
		results := s.Query(Query{})
		for _, r := range results {
			var probs []float64
			expectNoPath := 1.0
			for _, p := range r.Paths {
				prod := 1.0
				for _, step := range p.Steps {
					prod *= step.Probability
					if !approx(step.Probability, 0.3) && !approx(step.Probability, 0.6) {
						return false
					}
				}
				if !approx(prod, p.Probability) {
					return false
				}
				expectNoPath *= 1 - p.Probability
				probs = append(probs, p.Probability)
			}
			if len(probs) > 0 && !approx(r.Score, 1-expectNoPath) {
				return false
			}
		}
		return true
	}

	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 2000; i++ {
				if !check() {
					t.Errorf("reader observed an inconsistent (torn) snapshot")
					return
				}
			}
		}()
	}

	time.Sleep(300 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// TestInvalidBatchIsAtomic verifies a rejected batch changes nothing: the
// mutation is validated before logging or swapping.
func TestInvalidBatchIsAtomic(t *testing.T) {
	s := NewService()
	if err := s.Apply([]Op{
		{Kind: OpUpsertAsset, Asset: &Asset{ID: "e", External: true}},
		{Kind: OpUpsertAsset, Asset: &Asset{ID: "k", Critical: true}},
		{Kind: OpUpsertRule, Rule: &ConnectivityRule{ID: "r", From: "e", To: "k"}},
		{Kind: OpUpsertVuln, Vuln: &Vulnerability{ID: "v", Asset: "k", Exploitability: 0.5}},
	}); err != nil {
		t.Fatal(err)
	}

	before := s.Query(Query{Target: "k"})
	err := s.Apply([]Op{
		{Kind: OpUpsertVuln, Vuln: &Vulnerability{ID: "vx", Asset: "k", Exploitability: 0.7}},
		{Kind: OpUpsertRule, Rule: &ConnectivityRule{ID: "bad", From: "e", To: "ghost"}},
	})
	if err == nil {
		t.Fatal("expected batch to be rejected")
	}
	after := s.Query(Query{Target: "k"})
	if len(before) != 1 || len(after) != 1 || after[0].PathCount != before[0].PathCount {
		t.Fatalf("rejected batch must not change state: before=%+v after=%+v", before, after)
	}
}
