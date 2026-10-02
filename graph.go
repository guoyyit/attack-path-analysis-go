package attackpath

import "sort"

// ruleKey uniquely identifies a connectivity rule.
type ruleKey struct {
	src      string
	dst      string
	protocol string
	port     int
}

// step is a derived, exploitable directed edge.
type step struct {
	from string
	to   string
	vuln Vulnerability
	prob float64
}

// buildEdges derives the deterministic, de-duplicated attack edges from the
// inventory. A connectivity rule combined with a matching vulnerability on
// the destination produces one edge.
func buildEdges(m *material) []step {
	ruleKeys := make([]ruleKey, 0, len(m.rules))
	for k := range m.rules {
		ruleKeys = append(ruleKeys, k)
	}
	sortRuleKeys(ruleKeys)

	// Vulnerabilities grouped per target asset, sorted deterministically.
	vulnsByAsset := map[string][]Vulnerability{}
	for _, v := range m.vulns {
		vulnsByAsset[v.AssetID] = append(vulnsByAsset[v.AssetID], v)
	}
	for id := range vulnsByAsset {
		vs := vulnsByAsset[id]
		sort.Slice(vs, func(i, j int) bool { return vs[i].ID < vs[j].ID })
		vulnsByAsset[id] = vs
	}

	seen := map[[3]string]bool{}
	var edges []step
	for _, k := range ruleKeys {
		r := m.rules[k]
		for _, v := range vulnsByAsset[r.DstID] {
			if !protocolMatches(v.Protocol, r.Protocol) || !portMatches(v.Port, r.Port) {
				continue
			}
			dedup := [3]string{r.SrcID, r.DstID, v.ID}
			if seen[dedup] {
				continue
			}
			seen[dedup] = true
			edges = append(edges, step{
				from: r.SrcID,
				to:   r.DstID,
				vuln: v,
				prob: v.Exploitability,
			})
		}
	}

	// An asset explicitly flagged External is directly reachable from the
	// internet even without a modelled inbound rule. Synthesize one
	// deterministic, always-succeeds edge so reachability and path
	// enumeration share a single source of truth.
	externalIDs := make([]string, 0)
	for id, a := range m.assets {
		if a.External {
			externalIDs = append(externalIDs, id)
		}
	}
	sort.Strings(externalIDs)
	for _, id := range externalIDs {
		dedup := [3]string{InternetID, id, ExternalAccessVulnID}
		if seen[dedup] {
			continue
		}
		hasRealInternetEdge := false
		for _, e := range edges {
			if e.from == InternetID && e.to == id {
				hasRealInternetEdge = true
				break
			}
		}
		if hasRealInternetEdge {
			continue
		}
		seen[dedup] = true
		edges = append(edges, step{
			from: InternetID,
			to:   id,
			vuln: Vulnerability{ID: ExternalAccessVulnID, AssetID: id, Exploitability: 1},
			prob: 1,
		})
	}
	sortEdges(edges)
	return edges
}

// findEntries returns external entry assets: targets of internet-origin
// connectivity rules plus assets explicitly flagged External.
func findEntries(m *material, edges []step) []string {
	entries := map[string]bool{}
	for _, e := range edges {
		if e.from == InternetID {
			entries[e.to] = true
		}
	}
	return sortedAssetIDs(entries)
}

// reachResult is the least fixed point of the exploitation relation.
type reachResult struct {
	reached map[string]bool
	caps    map[string]bool
}

// computeReach evaluates preconditions and trust propagation until a fixed
// point. Cycles terminate because state only grows across finite sets.
func computeReach(edges []step, m *material, starts []string) reachResult {
	seeds := map[string]bool{}
	for _, s := range starts {
		seeds[s] = true
	}
	return computeReachSeeded(edges, m, seeds, map[string]bool{})
}

// computeReachSeeded evaluates the least fixed point starting from seed
// nodes with pre-existing capabilities. It is used both for a full
// derivation and an incremental one.
func computeReachSeeded(edges []step, m *material, seeds map[string]bool, initialCaps map[string]bool) reachResult {
	res := reachResult{
		reached: map[string]bool{},
		caps:    cloneBoolSet(initialCaps),
	}
	out := map[string][]step{}
	for _, e := range edges {
		out[e.from] = append(out[e.from], e)
	}
	var queue []string
	addCaps := func(caps []string) bool {
		grew := false
		for _, c := range caps {
			if !res.caps[c] {
				res.caps[c] = true
				grew = true
			}
		}
		return grew
	}
	reach := func(node string) bool {
		if res.reached[node] {
			return false
		}
		res.reached[node] = true
		queue = append(queue, node)
		if a, ok := m.assets[node]; ok {
			addCaps(a.Grants)
		}
		return true
	}
	for _, s := range sortedAssetIDs(seeds) {
		if s != InternetID {
			if _, ok := m.assets[s]; !ok {
				continue
			}
		}
		reach(s)
	}

	// A node is processed once per queue appearance. Re-enqueueing happens
	// only when a brand-new capability appears, and capabilities form a
	// finite set, so the loop always reaches a fixed point (cycles included).
	for head := 0; head < len(queue); head++ {
		node := queue[head]
		for _, e := range out[node] {
			if res.reached[e.to] || !hasCaps(res.caps, e.vuln.Requires) {
				continue
			}
			grewCaps := addCaps(e.vuln.Grants)
			reach(e.to)
			if grewCaps {
				// Previously unavailable edges may now fire; revisit every
				// reached node deterministically.
				for _, id := range sortedAssetIDs(res.reached) {
					queue = append(queue, id)
				}
			}
		}
	}
	return res
}

func protocolMatches(vulnProto, ruleProto string) bool {
	return vulnProto == "" || ruleProto == "" || vulnProto == ruleProto
}

func portMatches(vulnPort, rulePort int) bool {
	return vulnPort == 0 || rulePort == 0 || vulnPort == rulePort
}

func hasCaps(held map[string]bool, required []string) bool {
	for _, c := range required {
		if !held[c] {
			return false
		}
	}
	return true
}

func uniqueSorted(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func sortRuleKeys(keys []ruleKey) {
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.src != b.src {
			return a.src < b.src
		}
		if a.dst != b.dst {
			return a.dst < b.dst
		}
		if a.protocol != b.protocol {
			return a.protocol < b.protocol
		}
		return a.port < b.port
	})
}

func sortSteps(steps []step) {
	sort.Slice(steps, func(i, j int) bool {
		a, b := steps[i], steps[j]
		if a.from != b.from {
			return a.from < b.from
		}
		if a.to != b.to {
			return a.to < b.to
		}
		return a.vuln.ID < b.vuln.ID
	})
}

// sortEdges orders edges by source, destination then vulnerability id.
func sortEdges(edges []step) {
	sortSteps(edges)
}
