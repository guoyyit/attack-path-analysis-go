package attackpath

import "sort"

// deriveCompromised computes the attacker reachability fixpoint: an asset is
// compromised when it is external, or when a compromised source asset can
// exploit one of its vulnerabilities over a satisfying connectivity rule.
// Iteration order is deterministic (sorted ids), so the fixpoint is
// independent of input insertion order and always terminates in the presence
// of cycles.
func deriveCompromised(g *graph) map[string]bool {
	comp := map[string]bool{}
	var ids []string
	for id, a := range g.assets {
		if a.External {
			comp[id] = true
		}
		ids = append(ids, id)
	}
	sort.Strings(ids)

	// Monotone fixpoint. Every iteration only adds assets, so a cycle can
	// never cause non-termination: at most len(assets) iterations run.
	for {
		progressed := false
		var active []string
		for _, id := range ids {
			if comp[id] {
				active = append(active, id)
			}
		}
		for _, src := range active {
			for _, rule := range g.ruleIndex[src] {
				dst := rule.To
				if comp[dst] {
					continue
				}
				for _, vuln := range g.vulnIndex[dst] {
					if canExploit(rule, vuln) {
						comp[dst] = true
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
	return comp
}

// enumeratePaths returns every simple (asset-acyclic) path from one of starts
// to target that satisfies c, sorted by descending probability with a
// deterministic tie-break.
func enumeratePaths(g *graph, starts []string, target string, c Constraint) []AttackPath {
	excluded := map[string]bool{}
	for _, id := range c.Exclude {
		excluded[id] = true
	}
	required := map[string]bool{}
	for _, id := range c.MustInclude {
		required[id] = true
	}

	var paths []AttackPath
	var walk func(cur string, steps []Step, visited map[string]bool)
	walk = func(cur string, steps []Step, visited map[string]bool) {
		if cur == target {
			for req := range required {
				if !visited[req] {
					return
				}
			}
			paths = append(paths, buildPath(target, steps))
			return
		}
		if c.MaxSteps > 0 && len(steps) >= c.MaxSteps {
			return
		}
		for _, rule := range g.ruleIndex[cur] {
			dst := rule.To
			if visited[dst] || excluded[dst] {
				continue
			}
			for _, vuln := range g.vulnIndex[dst] {
				if !canExploit(rule, vuln) {
					continue
				}
				visited[dst] = true
				steps = append(steps, Step{
					From:        cur,
					To:          dst,
					RuleID:      rule.ID,
					VulnID:      vuln.ID,
					Probability: vuln.Exploitability,
				})
				walk(dst, steps, visited)
				steps = steps[:len(steps)-1]
				delete(visited, dst)
			}
		}
	}

	for _, start := range starts {
		if excluded[start] {
			continue
		}
		visited := map[string]bool{start: true}
		walk(start, nil, visited)
	}

	sort.Slice(paths, func(i, j int) bool {
		if paths[i].Probability != paths[j].Probability {
			return paths[i].Probability > paths[j].Probability
		}
		return pathKey(paths[i]) < pathKey(paths[j])
	})
	return paths
}

// scoreRisk aggregates path probabilities for one asset using the
// probability of at least one independent path:
//
//	score = 1 - Π(1 - pathProbability)
//
// Paths are first de-duplicated and deterministically ordered so the result is
// reproducible and input-order independent.
func scoreRisk(g *graph, assetID string, paths []AttackPath) *AssetRisk {
	uniq := make(map[string]AttackPath, len(paths))
	for _, p := range paths {
		uniq[pathKey(p)] = p
	}
	ordered := make([]AttackPath, 0, len(uniq))
	for _, p := range uniq {
		ordered = append(ordered, p)
	}
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Probability != ordered[j].Probability {
			return ordered[i].Probability > ordered[j].Probability
		}
		return pathKey(ordered[i]) < pathKey(ordered[j])
	})

	// Independent-step probability and independent-path aggregation, so the
	// product/1-product form is independent of evaluation order.
	noPath := 1.0
	for _, p := range ordered {
		noPath *= 1 - p.Probability
	}
	score := 1 - noPath
	if len(ordered) == 0 {
		score = 0
	}
	return &AssetRisk{
		AssetID:   assetID,
		Score:     score,
		PathCount: len(ordered),
		Paths:     ordered,
	}
}

func buildPath(target string, steps []Step) AttackPath {
	start := target
	if len(steps) > 0 {
		start = steps[0].From
	}
	cp := make([]Step, len(steps))
	copy(cp, steps)
	prob := 1.0
	for _, s := range cp {
		prob *= s.Probability
	}
	return AttackPath{Start: start, Target: target, Steps: cp, Probability: prob}
}

// pathKey is a deterministic canonical identity for a path, used for
// de-duplication and ordering so results never depend on insertion order.
func pathKey(p AttackPath) string {
	key := p.Start
	for _, s := range p.Steps {
		key += ">" + s.To + ":" + s.RuleID + ":" + s.VulnID
	}
	return key
}
