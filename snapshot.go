package attackpath

import (
	"encoding/json"
	"errors"
	"math"
	"sort"
)

// material is the persisted inventory state: the raw facts the derived
// attack graph is computed from.
type material struct {
	assets map[string]Asset
	vulns  map[string]Vulnerability
	rules  map[ruleKey]ConnectRule
}

type persistedMaterial struct {
	Assets []Asset         `json:"assets"`
	Vulns  []Vulnerability `json:"vulns"`
	Rules  []ConnectRule   `json:"rules"`
}

// MarshalJSON emits facts in deterministic (ID/endpoint) order so persisted
// output is reproducible and input-order independent.
func (m material) MarshalJSON() ([]byte, error) {
	pm := persistedMaterial{
		Assets: make([]Asset, 0, len(m.assets)),
		Vulns:  make([]Vulnerability, 0, len(m.vulns)),
		Rules:  make([]ConnectRule, 0, len(m.rules)),
	}
	for _, id := range sortedMapKeys(m.assets) {
		pm.Assets = append(pm.Assets, m.assets[id])
	}
	vulnIDs := make([]string, 0, len(m.vulns))
	for id := range m.vulns {
		vulnIDs = append(vulnIDs, id)
	}
	sort.Strings(vulnIDs)
	for _, id := range vulnIDs {
		pm.Vulns = append(pm.Vulns, m.vulns[id])
	}
	ruleKeys := make([]ruleKey, 0, len(m.rules))
	for k := range m.rules {
		ruleKeys = append(ruleKeys, k)
	}
	sortRuleKeys(ruleKeys)
	for _, k := range ruleKeys {
		pm.Rules = append(pm.Rules, m.rules[k])
	}
	return json.Marshal(pm)
}

func (m *material) UnmarshalJSON(data []byte) error {
	var pm persistedMaterial
	if err := json.Unmarshal(data, &pm); err != nil {
		return err
	}
	m.assets = map[string]Asset{}
	m.vulns = map[string]Vulnerability{}
	m.rules = map[ruleKey]ConnectRule{}
	for _, a := range pm.Assets {
		m.assets[a.ID] = a
	}
	for _, v := range pm.Vulns {
		m.vulns[v.ID] = v
	}
	for _, r := range pm.Rules {
		m.rules[ruleOf(r)] = r
	}
	return nil
}

// Snapshot is an immutable, consistent view of the attack model. Query
// methods never observe partially applied updates.
type Snapshot struct {
	version int64
	material
	edges   []step
	out     map[string][]int
	entries []string
	reached map[string]bool
	caps    map[string]bool
	report  *Report
}

// newMaterial returns an empty inventory.
func newMaterial() material {
	return material{
		assets: map[string]Asset{},
		vulns:  map[string]Vulnerability{},
		rules:  map[ruleKey]ConnectRule{},
	}
}

// Version returns the monotonically increasing snapshot version.
func (s *Snapshot) Version() int64 { return s.version }

// Entries returns external entry assets in deterministic order.
func (s *Snapshot) Entries() []string { return append([]string(nil), s.entries...) }

// Reachable returns every externally reachable asset in deterministic order.
func (s *Snapshot) Reachable() []string {
	out := make([]string, 0, len(s.reached))
	for id := range s.reached {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// IsReachable reports whether id is compromised in this snapshot.
func (s *Snapshot) IsReachable(id string) bool { return s.reached[id] }

// cloneMaterial deep-copies the inventory so old snapshots stay immutable.
func cloneMaterial(m material) material {
	c := material{
		assets: make(map[string]Asset, len(m.assets)),
		vulns:  make(map[string]Vulnerability, len(m.vulns)),
		rules:  make(map[ruleKey]ConnectRule, len(m.rules)),
	}
	for id, a := range m.assets {
		na := a
		na.Grants = cloneStrings(a.Grants)
		if a.Attrs != nil {
			na.Attrs = make(map[string]string, len(a.Attrs))
			for k, v := range a.Attrs {
				na.Attrs[k] = v
			}
		}
		c.assets[id] = na
	}
	for id, v := range m.vulns {
		nv := v
		nv.Requires = cloneStrings(v.Requires)
		nv.Grants = cloneStrings(v.Grants)
		c.vulns[id] = nv
	}
	for k, r := range m.rules {
		c.rules[k] = r
	}
	return c
}

// applyMaterial mutates a material copy with the batch and returns the set
// of asset IDs whose derived state may have changed.
func applyMaterial(m material, cs ChangeSet) (map[string]bool, error) {
	if err := validateChangeSet(cs); err != nil {
		return nil, err
	}
	touched := map[string]bool{}

	assetByID := map[string]Asset{}
	for _, a := range cs.UpsertAssets {
		assetByID[a.ID] = a
	}
	vulnByID := map[string]Vulnerability{}
	for _, v := range cs.UpsertVulns {
		vulnByID[v.ID] = v
	}
	ruleByKey := map[ruleKey]ConnectRule{}
	for _, r := range cs.UpsertRules {
		ruleByKey[ruleOf(r)] = r
	}

	deleteAssets := uniqueStrings(cs.DeleteAssets)
	deleteVulns := uniqueStrings(cs.DeleteVulns)

	// Seed the dirty region from every endpoint before the graph changes.
	for id := range assetByID {
		touchNeighbors(m, touched, id)
	}
	for _, id := range deleteAssets {
		touchNeighbors(m, touched, id)
	}
	for _, v := range vulnByID {
		touchNeighbors(m, touched, v.AssetID)
	}
	for _, id := range deleteVulns {
		if v, ok := m.vulns[id]; ok {
			touchNeighbors(m, touched, v.AssetID)
		}
	}
	for _, r := range ruleByKey {
		touchEndpoints(touched, r.SrcID, r.DstID)
	}
	for _, r := range cs.DeleteRules {
		if _, ok := m.rules[ruleOf(r)]; ok {
			touchEndpoints(touched, r.SrcID, r.DstID)
		}
	}

	// Upserts.
	for _, a := range assetByID {
		touched[a.ID] = true
		m.assets[a.ID] = a
	}
	for _, v := range vulnByID {
		touched[v.AssetID] = true
		m.vulns[v.ID] = v
	}
	for _, r := range ruleByKey {
		touchEndpoints(touched, r.SrcID, r.DstID)
		m.rules[ruleOf(r)] = r
	}

	// Deletes (applied after upserts: an ID both upserted and deleted is gone).
	for _, id := range deleteAssets {
		if _, ok := m.assets[id]; !ok {
			continue
		}
		touched[id] = true
		delete(m.assets, id)
		for vid, v := range m.vulns {
			if v.AssetID == id {
				delete(m.vulns, vid)
			}
		}
		for k, r := range m.rules {
			if r.SrcID == id || r.DstID == id {
				touchEndpoints(touched, r.SrcID, r.DstID)
				delete(m.rules, k)
			}
		}
	}
	for _, id := range deleteVulns {
		if v, ok := m.vulns[id]; ok {
			touched[v.AssetID] = true
		}
		delete(m.vulns, id)
	}
	for _, r := range cs.DeleteRules {
		k := ruleOf(r)
		if existing, ok := m.rules[k]; ok {
			touchEndpoints(touched, existing.SrcID, existing.DstID)
		}
		delete(m.rules, k)
	}

	if err := validateReferences(m); err != nil {
		return nil, err
	}

	// The pseudo internet node seeds the external entries.
	if touched[InternetID] {
		for id := range m.assets {
			touched[id] = true
		}
	}
	delete(touched, InternetID)
	return touched, nil
}

// buildSnapshot runs a full derivation from raw inventory facts.
func buildSnapshot(version int64, m material) *Snapshot {
	m = cloneMaterial(m)
	edges := buildEdges(&m)
	out := indexOut(edges)
	entries := findEntries(&m, edges)
	reach := computeReach(edges, &m, append([]string{InternetID}, entries...))
	snap := &Snapshot{
		version:  version,
		material: m,
		edges:    edges,
		out:      out,
		entries:  entries,
		reached:  reach.reached,
		caps:     reach.caps,
	}
	delete(snap.reached, InternetID)
	snap.report = buildReport(snap)
	return snap
}

// advanceSnapshot derives a new snapshot from newM, recomputing only edges
// incident to touched assets and the forward region they influence. The
// result equals a full rebuild exactly.
func advanceSnapshot(old *Snapshot, newM material, touched map[string]bool, version int64) *Snapshot {
	if len(touched) == 0 {
		snap := &Snapshot{
			version:  version,
			material: newM,
			edges:    old.edges,
			out:      old.out,
			entries:  old.entries,
			reached:  cloneBoolSet(old.reached),
			caps:     cloneBoolSet(old.caps),
		}
		snap.report = buildReport(snap)
		return snap
	}

	newEdges := rebuildEdges(old.edges, &newM, touched)
	entries := findEntries(&newM, newEdges)

	// Affected region: forward closure from touched nodes in BOTH the old
	// and new edge sets. Union is required so nodes reachable only through
	// a deleted edge are also reconsidered (correctly becoming unreachable).
	affected := cloneBoolSet(touched)
	forwardClosure(newEdges, affected)
	forwardClosure(old.edges, affected)

	// Seed the fixed point with external entries and every previously
	// reached node outside the affected region; derived state there is
	// provably unchanged.
	seeds := map[string]bool{InternetID: true}
	for _, id := range entries {
		seeds[id] = true
	}
	caps := map[string]bool{}
	for id := range old.reached {
		if !affected[id] {
			seeds[id] = true
		}
	}
	// Derive seed capabilities from the NEW facts only: seed nodes are all
	// reached at iteration zero, so their asset grants are valid regardless
	// of region membership. Capabilities granted solely by vulnerabilities
	// on affected nodes are re-derived by the fixed point along new edges,
	// never carried over stale.
	for id := range seeds {
		if a, ok := newM.assets[id]; ok {
			for _, c := range a.Grants {
				caps[c] = true
			}
		}
	}
	reach := computeReachSeeded(newEdges, &newM, seeds, caps)

	snap := &Snapshot{
		version:  version,
		material: newM,
		edges:    newEdges,
		out:      indexOut(newEdges),
		entries:  entries,
		reached:  reach.reached,
		caps:     reach.caps,
	}
	delete(snap.reached, InternetID)
	snap.report = buildReport(snap)
	return snap
}

func indexOut(edges []step) map[string][]int {
	out := map[string][]int{}
	for i, e := range edges {
		out[e.from] = append(out[e.from], i)
	}
	return out
}

func cloneBoolSet(in map[string]bool) map[string]bool {
	out := make(map[string]bool, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// forwardClosure grows set along directed edges.
func forwardClosure(edges []step, set map[string]bool) {
	changed := true
	for changed {
		changed = false
		for _, e := range edges {
			if set[e.from] && !set[e.to] {
				set[e.to] = true
				changed = true
			}
		}
	}
}

// rebuildEdges keeps edges whose endpoints are both untouched and derives
// every edge incident to a touched asset from the new material.
func rebuildEdges(oldEdges []step, newM *material, touched map[string]bool) []step {
	seen := map[[3]string]bool{}
	var merged []step
	for _, e := range oldEdges {
		if touched[e.from] || touched[e.to] {
			continue
		}
		key := [3]string{e.from, e.to, e.vuln.ID}
		if seen[key] {
			continue
		}
		seen[key] = true
		merged = append(merged, e)
	}
	for _, e := range buildEdges(newM) {
		if !touched[e.from] && !touched[e.to] {
			continue
		}
		key := [3]string{e.from, e.to, e.vuln.ID}
		if seen[key] {
			continue
		}
		seen[key] = true
		merged = append(merged, e)
	}
	sortEdges(merged)
	return merged
}

func ruleOf(r ConnectRule) ruleKey {
	return ruleKey{src: r.SrcID, dst: r.DstID, protocol: r.Protocol, port: r.Port}
}

func cloneStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

func uniqueStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := in[:0]
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func touchNeighbors(m material, touched map[string]bool, id string) {
	touched[id] = true
	for _, r := range m.rules {
		if r.SrcID == id || r.DstID == id {
			touchEndpoints(touched, r.SrcID, r.DstID)
		}
	}
}

func touchEndpoints(touched map[string]bool, ids ...string) {
	for _, id := range ids {
		if id != InternetID {
			touched[id] = true
		}
	}
}

func validateChangeSet(cs ChangeSet) error {
	seenAssets := map[string]bool{}
	for _, a := range cs.UpsertAssets {
		if a.ID == "" {
			return errors.New("asset id must not be empty")
		}
		if seenAssets[a.ID] {
			return errors.New("duplicate asset upsert in batch: " + a.ID)
		}
		seenAssets[a.ID] = true
	}
	seenVulns := map[string]bool{}
	for _, v := range cs.UpsertVulns {
		if v.ID == "" {
			return errors.New("vulnerability id must not be empty")
		}
		if v.AssetID == "" {
			return errors.New("vulnerability asset_id must not be empty: " + v.ID)
		}
		if math.IsNaN(v.Exploitability) || math.IsInf(v.Exploitability, 0) ||
			v.Exploitability < 0 || v.Exploitability > 1 {
			return errors.New("vulnerability exploitability must be within [0,1]: " + v.ID)
		}
		if seenVulns[v.ID] {
			return errors.New("duplicate vulnerability upsert in batch: " + v.ID)
		}
		seenVulns[v.ID] = true
	}
	for _, r := range cs.UpsertRules {
		if r.SrcID == "" || r.DstID == "" {
			return errors.New("connectivity rule endpoints must not be empty")
		}
	}
	return nil
}

func validateReferences(m material) error {
	for _, v := range m.vulns {
		if _, ok := m.assets[v.AssetID]; !ok {
			return errors.New("vulnerability references unknown asset: " + v.AssetID)
		}
	}
	for _, r := range m.rules {
		if r.SrcID != InternetID {
			if _, ok := m.assets[r.SrcID]; !ok {
				return errors.New("connectivity rule references unknown source asset: " + r.SrcID)
			}
		}
		if _, ok := m.assets[r.DstID]; !ok {
			return errors.New("connectivity rule references unknown destination asset: " + r.DstID)
		}
	}
	return nil
}

// sortedAssetIDs returns the asset IDs in lexicographic order.
func sortedAssetIDs(ids map[string]bool) []string {
	out := make([]string, 0, len(ids))
	for id := range ids {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func sortedMapKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for id := range m {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
