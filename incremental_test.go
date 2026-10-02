package attackpath

import (
	"fmt"
	"math/rand"
	"reflect"
	"sort"
	"testing"
)

// canonicalSnapshot compares only the derived conclusions: compromise set,
// per-asset risk score and the canonical path sets.
func canonicalSnapshot(g *graph) map[string]any {
	out := map[string]any{}
	comp := []string{}
	for id, c := range g.compromised {
		if c {
			comp = append(comp, id)
		}
	}
	sort.Strings(comp)
	out["compromised"] = comp

	risks := map[string]string{}
	ids := make([]string, 0, len(g.risks))
	for id := range g.risks {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		r := g.risks[id]
		paths := []string{}
		for _, p := range r.Paths {
			paths = append(paths, pathKey(p))
		}
		risks[id] = fmt.Sprintf("%.12f|%d|%v", r.Score, r.PathCount, paths)
	}
	out["risks"] = risks
	return out
}

const (
	nAssets    = 14
	capNetwork = "network"
	capSSH     = "ssh"
	capAdmin   = "admin"
)

var allCaps = []string{capNetwork, capSSH, capAdmin}

func randomOps(rng *rand.Rand) []Op {
	nAssets := 1 + rng.Intn(nAssets)
	nRules := rng.Intn(nAssets * 3)
	nVulns := rng.Intn(nAssets * 3)

	ops := []Op{}
	for i := 0; i < nAssets; i++ {
		ops = append(ops, Op{
			Kind: OpUpsertAsset,
			Asset: &Asset{
				ID:       fmt.Sprintf("a%02d", i),
				External: rng.Intn(100) < 25,
				Critical: rng.Intn(100) < 30,
				Type:     "host",
			},
		})
	}
	// Rules are added after all assets so references always resolve.
	for i := 0; i < nRules; i++ {
		from := rng.Intn(nAssets)
		to := rng.Intn(nAssets)
		caps := []string{capNetwork}
		if rng.Intn(2) == 0 {
			caps = append(caps, allCaps[1+rng.Intn(len(allCaps)-1)])
		}
		ops = append(ops, Op{
			Kind: OpUpsertRule,
			Rule: &ConnectivityRule{
				ID:           fmt.Sprintf("r%03d", i),
				From:         fmt.Sprintf("a%02d", from),
				To:           fmt.Sprintf("a%02d", to),
				Capabilities: caps,
			},
		})
	}
	for i := 0; i < nVulns; i++ {
		pre := []string{capNetwork}
		if rng.Intn(2) == 0 {
			pre = append(pre, allCaps[1+rng.Intn(len(allCaps)-1)])
		}
		ops = append(ops, Op{
			Kind: OpUpsertVuln,
			Vuln: &Vulnerability{
				ID:             fmt.Sprintf("v%03d", i),
				Asset:          fmt.Sprintf("a%02d", rng.Intn(nAssets)),
				Exploitability: roundProb(rng.Float64()),
				Preconditions:  pre,
			},
		})
	}
	return ops
}

func roundProb(p float64) float64 {
	return float64(int(p*100)) / 100
}

// randomMutation builds a valid mutation against the current state.
func randomMutation(rng *rand.Rand, g *graph) Op {
	switch rng.Intn(6) {
	case 0, 1: // upsert/modify asset
		id := pickAssetID(rng, g)
		return Op{Kind: OpUpsertAsset, Asset: &Asset{
			ID:       id,
			External: rng.Intn(100) < 25,
			Critical: rng.Intn(100) < 30,
		}}
	case 2: // upsert/modify rule
		rid := fmt.Sprintf("r%03d", rng.Intn(nAssets*3))
		caps := []string{capNetwork}
		if rng.Intn(2) == 0 {
			caps = append(caps, allCaps[1+rng.Intn(len(allCaps)-1)])
		}
		return Op{Kind: OpUpsertRule, Rule: &ConnectivityRule{
			ID: rid, From: pickAssetID(rng, g), To: pickAssetID(rng, g), Capabilities: caps,
		}}
	case 3: // delete a rule
		ids := make([]string, 0, len(g.rules))
		for id := range g.rules {
			ids = append(ids, id)
		}
		if len(ids) == 0 {
			return randomMutation(rng, g)
		}
		return Op{Kind: OpDeleteRule, Rule: &ConnectivityRule{ID: ids[rng.Intn(len(ids))]}}
	case 4: // upsert/modify vuln
		pre := []string{capNetwork}
		if rng.Intn(2) == 0 {
			pre = append(pre, allCaps[1+rng.Intn(len(allCaps)-1)])
		}
		return Op{Kind: OpUpsertVuln, Vuln: &Vulnerability{
			ID:             fmt.Sprintf("v%03d", rng.Intn(nAssets*3)),
			Asset:          pickAssetID(rng, g),
			Exploitability: roundProb(rng.Float64()),
			Preconditions:  pre,
		}}
	default: // delete a vuln
		ids := make([]string, 0, len(g.vulns))
		for id := range g.vulns {
			ids = append(ids, id)
		}
		if len(ids) == 0 {
			return randomMutation(rng, g)
		}
		return Op{Kind: OpDeleteVuln, Vuln: &Vulnerability{ID: ids[rng.Intn(len(ids))]}}
	}
}

func pickAssetID(rng *rand.Rand, g *graph) string {
	ids := make([]string, 0, len(g.assets))
	for id := range g.assets {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids[rng.Intn(len(ids))]
}

func TestIncrementalMatchesRebuild(t *testing.T) {
	for seed := int64(1); seed <= 40; seed++ {
		rng := rand.New(rand.NewSource(seed))
		g := emptyGraph(0)
		g = newGraph(0, nil, nil, nil)

		var batch []Op
		flush := func() {
			if len(batch) == 0 {
				return
			}
			next, err := g.apply(g.version+1, batch)
			if err != nil {
				t.Fatalf("seed=%d apply error: %v", seed, err)
			}
			reb := next.rebuild(next.version)
			if !reflect.DeepEqual(canonicalSnapshot(next), canonicalSnapshot(reb)) {
				t.Fatalf("seed=%d incremental != rebuild after %d steps\ninc=%v\nreb=%v",
					seed, next.version, canonicalSnapshot(next), canonicalSnapshot(reb))
			}
			g = next
			batch = nil
		}

		for _, op := range randomOps(rng) {
			batch = append(batch, op)
			if rng.Intn(3) == 0 {
				flush()
			}
		}
		flush()

		// Mutations, including deletions, in random batches.
		for step := 0; step < 300; step++ {
			batchSize := 1 + rng.Intn(4)
			for i := 0; i < batchSize; i++ {
				batch = append(batch, randomMutation(rng, g))
			}
			flush()
		}
	}
}

func TestIncrementalWithAssetDeletion(t *testing.T) {
	rng := rand.New(rand.NewSource(99))
	g := emptyGraph(0)
	var batch []Op
	for _, op := range randomOps(rng) {
		batch = append(batch, op)
	}
	var err error
	g, err = g.apply(1, batch)
	if err != nil {
		t.Fatal(err)
	}

	for step := 0; step < 200; step++ {
		var op Op
		if step%3 == 0 {
			id := pickAssetID(rng, g)
			op = Op{Kind: OpDeleteAsset, Asset: &Asset{ID: id}}
		} else if step%3 == 1 {
			n := len(g.assets)
			op = Op{Kind: OpUpsertAsset, Asset: &Asset{
				ID:       fmt.Sprintf("a%02d", n),
				External: rng.Intn(2) == 0,
				Critical: rng.Intn(2) == 0,
			}}
		} else {
			op = randomMutation(rng, g)
		}
		next, err := g.apply(g.version+1, []Op{op})
		if err != nil {
			t.Fatalf("step %d: %v", step, err)
		}
		reb := next.rebuild(next.version)
		if !reflect.DeepEqual(canonicalSnapshot(next), canonicalSnapshot(reb)) {
			t.Fatalf("step %d incremental != rebuild\ninc=%v\nreb=%v",
				step, canonicalSnapshot(next), canonicalSnapshot(reb))
		}
		g = next
	}
}

func TestInputOrderIndependence(t *testing.T) {
	base := randomOps(rand.New(rand.NewSource(7)))
	shuffled := append([]Op(nil), base...)
	rng := rand.New(rand.NewSource(777))
	rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })

	// Asset upserts must precede references for each batch to validate;
	// apply in two batches to keep references valid but shuffle the rest.
	g1 := newGraph(1, nil, nil, nil)
	g1, err := g1.apply(1, base)
	if err != nil {
		t.Fatal(err)
	}

	var assets, rest []Op
	for _, op := range shuffled {
		if op.Kind == OpUpsertAsset {
			assets = append(assets, op)
		} else {
			rest = append(rest, op)
		}
	}
	g2 := newGraph(1, nil, nil, nil)
	g2, err = g2.apply(1, assets)
	if err != nil {
		t.Fatal(err)
	}
	g2, err = g2.apply(2, rest)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(canonicalSnapshot(g1), canonicalSnapshot(g2)) {
		t.Fatalf("results depend on input insertion order")
	}
}
