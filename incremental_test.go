package attackpath

import (
	"math/rand"
	"testing"
)

// fullRebuildService replays every committed batch onto a fresh engine,
// giving the reference full-rebuild state.
type fullRebuildService struct {
	batches []ChangeSet
}

func (f *fullRebuildService) snapshot(t *testing.T) *Snapshot {
	t.Helper()
	svc, err := Open("")
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	for _, b := range f.batches {
		if err := svc.Update(b); err != nil {
			t.Fatalf("rebuild update: %v", err)
		}
	}
	return svc.Current()
}

func randomBatches(rng *rand.Rand, n int) []ChangeSet {
	assets := []string{"a0", "a1", "a2", "a3", "a4", "a5"}
	protos := []string{"tcp", "udp", ""}
	var batches []ChangeSet
	for i := 0; i < n; i++ {
		cs := ChangeSet{}
		switch rng.Intn(6) {
		case 0:
			id := assets[rng.Intn(len(assets))]
			cs.UpsertAssets = []Asset{{
				ID:       id,
				External: rng.Intn(3) == 0,
				Critical: rng.Intn(4) == 0,
				Grants:   maybeGrants(rng, id),
			}}
		case 1:
			id := "v" + itoa(rng.Intn(12))
			cs.UpsertVulns = []Vulnerability{{
				ID:             id,
				AssetID:        assets[rng.Intn(len(assets))],
				Exploitability: roundProb(rng.Float64()),
				Protocol:       protos[rng.Intn(len(protos))],
				Port:           rng.Intn(3) * 80,
				Requires:       maybeCaps(rng),
				Grants:         maybeCaps(rng),
			}}
		case 2:
			src := assets[rng.Intn(len(assets))]
			if rng.Intn(4) == 0 {
				src = InternetID
			}
			dst := assets[rng.Intn(len(assets))]
			cs.UpsertRules = []ConnectRule{{
				SrcID:    src,
				DstID:    dst,
				Protocol: protos[rng.Intn(len(protos))],
				Port:     1000 + rng.Intn(4)*10,
			}}
		case 3:
			cs.DeleteVulns = []string{"v" + itoa(rng.Intn(12))}
		case 4:
			src := assets[rng.Intn(len(assets))]
			dst := assets[rng.Intn(len(assets))]
			cs.DeleteRules = []ConnectRule{{SrcID: src, DstID: dst}}
		case 5:
			cs.DeleteRules = []ConnectRule{{SrcID: InternetID, DstID: assets[rng.Intn(len(assets))], Protocol: "tcp"}}
		}
		batches = append(batches, cs)
	}
	return batches
}

func maybeGrants(rng *rand.Rand, id string) []string {
	if rng.Intn(2) == 0 {
		return []string{"cap-" + id}
	}
	return nil
}

func maybeCaps(rng *rand.Rand) []string {
	if rng.Intn(2) == 0 {
		return []string{"cap-a" + itoa(rng.Intn(6))}
	}
	return nil
}

func roundProb(p float64) float64 {
	return float64(int(p*100)) / 100
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

func TestIncrementalMatchesFullRebuild(t *testing.T) {
	for seed := int64(0); seed < 20; seed++ {
		t.Run("seed", func(t *testing.T) {
			rng := rand.New(rand.NewSource(seed))
			batches := randomBatches(rng, 60)

			inc, err := Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer inc.Close()
			seedAssets := ChangeSet{}
			for _, id := range []string{"a0", "a1", "a2", "a3", "a4", "a5"} {
				seedAssets.UpsertAssets = append(seedAssets.UpsertAssets, Asset{ID: id})
			}
			if err := inc.Update(seedAssets); err != nil {
				t.Fatal(err)
			}
			ref := &fullRebuildService{}
			ref.batches = append(ref.batches, seedAssets)

			for i, b := range batches {
				if err := inc.Update(b); err != nil {
					t.Fatalf("seed %d step %d: unexpected batch error: %v", seed, i, err)
				}
				ref.batches = append(ref.batches, b)

				got := inc.Current()
				want := ref.snapshot(t)
				if !snapshotsEqual(got, want) {
					t.Fatalf("seed %d step %d:\nincremental=%s\nfull=%s",
						seed, i, dumpSnapshot(got), dumpSnapshot(want))
				}
			}
		})
	}
}

func snapshotsEqual(a, b *Snapshot) bool {
	if a.version != b.version {
		return false
	}
	if !equalStrings(a.entries, b.entries) {
		return false
	}
	if !equalStringSets(keysBool(a.reached), keysBool(b.reached)) {
		return false
	}
	if !equalStringSets(keysBool(a.caps), keysBool(b.caps)) {
		return false
	}
	if len(a.edges) != len(b.edges) {
		return false
	}
	for i := range a.edges {
		ea, eb := a.edges[i], b.edges[i]
		if ea.from != eb.from || ea.to != eb.to || ea.vuln.ID != eb.vuln.ID || ea.prob != eb.prob {
			return false
		}
	}
	ra, rb := a.report, b.report
	if !equalStrings(ra.Reachable, rb.Reachable) {
		return false
	}
	if len(ra.Risks) != len(rb.Risks) {
		return false
	}
	for id, x := range ra.Risks {
		y := rb.Risks[id]
		if y == nil || len(x.Paths) != len(y.Paths) {
			return false
		}
		for i := range x.Paths {
			if !equalStrings(x.Paths[i].Nodes, y.Paths[i].Nodes) {
				return false
			}
			stepEq := len(x.Paths[i].Steps) == len(y.Paths[i].Steps)
			if stepEq {
				for j := range x.Paths[i].Steps {
					if x.Paths[i].Steps[j].VulnID != y.Paths[i].Steps[j].VulnID {
						stepEq = false
						break
					}
				}
			}
			if !stepEq || x.Paths[i].Risk != y.Paths[i].Risk {
				return false
			}
		}
	}
	return true
}

func keysBool(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func dumpSnapshot(s *Snapshot) string {
	out := "entries=" + fmtJoin(s.entries) + " reached=" + fmtJoin(keysBool(s.reached))
	return out
}

func fmtJoin(in []string) string {
	out := "["
	for i, s := range in {
		if i > 0 {
			out += " "
		}
		out += s
	}
	return out + "]"
}
