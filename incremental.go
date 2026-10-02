package attackpath

import "sort"

// affectedRegion returns the set of assets whose derived conclusions
// (compromise status or risk) can possibly change moving from old to next.
// The region is computed downstream (forward along the new rule edges) from
// the mutation seeds; recomputing within it yields exactly the same result as
// a from-scratch rebuild, including for rule and vulnerability deletions.
func affectedRegion(old, next *graph, seeds map[string]bool) map[string]bool {
	region := map[string]bool{}
	queue := make([]string, 0, len(seeds))
	for id := range seeds {
		if _, ok := next.assets[id]; ok && !region[id] {
			region[id] = true
			queue = append(queue, id)
		}
	}
	// Forward closure along the *new* edges. Every conclusion reachable from
	// a seed may change; everything outside the closure provably cannot,
	// even under deletions: deleting data only removes evidence flowing
	// downstream of the touched endpoints.
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, r := range next.ruleIndex[cur] {
			if !region[r.To] {
				if _, ok := next.assets[r.To]; ok {
					region[r.To] = true
					queue = append(queue, r.To)
				}
			}
		}
	}
	return region
}

// rederiveRegion reruns the reachability fixpoint restricted to region while
// treating facts outside it as fixed, then refreshes risk scores.
func rederiveRegion(g *graph, region map[string]bool) {
	for id := range region {
		delete(g.compromised, id)
	}

	ids := make([]string, 0, len(g.assets))
	for id := range g.assets {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	for id, a := range g.assets {
		if a.External {
			g.compromised[id] = true
		}
	}

	// Fixpoint over the full graph with region facts reset; facts outside the
	// region retain their previous values and edges never flow out of the
	// region into a non-region node, so the result equals a full rebuild.
	for {
		progressed := false
		var active []string
		for _, id := range ids {
			if g.compromised[id] {
				active = append(active, id)
			}
		}
		for _, src := range active {
			for _, rule := range g.ruleIndex[src] {
				dst := rule.To
				if g.compromised[dst] {
					continue
				}
				for _, vuln := range g.vulnIndex[dst] {
					if canExploit(rule, vuln) {
						g.compromised[dst] = true
						progressed = true
						break
					}
				}
			}
		}
		if !progressed {
			break
		}
	}

	var starts []string
	for id, a := range g.assets {
		if a.External {
			starts = append(starts, id)
		}
	}
	sort.Strings(starts)

	for id := range region {
		delete(g.risks, id)
		asset, ok := g.assets[id]
		if !ok {
			continue
		}
		if asset.External {
			g.risks[id] = &AssetRisk{AssetID: id, Score: 1}
			continue
		}
		paths := enumeratePaths(g, starts, id, Constraint{})
		if len(paths) > 0 {
			g.risks[id] = scoreRisk(g, id, paths)
		}
	}
}
