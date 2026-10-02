package attackpath

import (
	"errors"
	"sort"
)

// DefaultMaxSteps bounds simple path enumeration so a dense graph cannot
// produce an exponentially unbounded result. It can be overridden per query.
const DefaultMaxSteps = 12

// enumeratePaths returns every simple path admitted by the constraint,
// ordered by descending risk then lexicographic node sequence.
func enumeratePaths(snap *Snapshot, c Constraint) []AttackPath {
	c = normalizeConstraint(c)

	targetSet := toStringSet(c.Targets)
	required := toStringSet(c.Required)
	excluded := toStringSet(c.Excluded)
	maxLen := c.MaxLength
	if maxLen <= 0 {
		maxLen = DefaultMaxSteps
	}

	var result []AttackPath
	var dfs func(node string, nodes []string, steps []Step, visited map[string]bool, held map[string]bool, prob float64)
	dfs = func(node string, nodes []string, steps []Step, visited map[string]bool, held map[string]bool, prob float64) {
		if targetSet[node] && containsAll(nodes, required) {
			path := AttackPath{
				Nodes: append([]string(nil), nodes...),
				Steps: append([]Step(nil), steps...),
				Risk:  prob,
			}
			result = append(result, path)
		}
		if len(steps) >= maxLen {
			return
		}
		for _, idx := range snap.out[node] {
			e := snap.edges[idx]
			if visited[e.to] || excluded[e.to] {
				continue
			}
			if !hasCaps(held, e.vuln.Requires) {
				continue
			}
			visited[e.to] = true
			nextHeld := cloneStringSet(held)
			for _, c := range e.vuln.Grants {
				nextHeld[c] = true
			}
			if a, ok := snap.assets[e.to]; ok {
				for _, c := range a.Grants {
					nextHeld[c] = true
				}
			}
			dfs(e.to, append(nodes, e.to),
				append(steps, Step{From: e.from, To: e.to, VulnID: e.vuln.ID, Risk: e.prob}),
				visited, nextHeld, prob*e.prob)
			delete(visited, e.to)
		}
	}

	for _, start := range c.Starts {
		if excluded[start] {
			continue
		}
		// Direct zero-hop match: a start that is itself a target.
		visited := map[string]bool{start: true}
		held := map[string]bool{}
		if a, ok := snap.assets[start]; ok {
			for _, c := range a.Grants {
				held[c] = true
			}
		}
		dfs(start, []string{start}, nil, visited, held, 1)
	}

	result = dedupPaths(result)
	sortPaths(result)
	return result
}

func cloneStringSet(in map[string]bool) map[string]bool {
	out := make(map[string]bool, len(in))
	for k := range in {
		out[k] = true
	}
	return out
}

// sortPaths orders paths deterministically.
func sortPaths(paths []AttackPath) {
	sort.Slice(paths, func(i, j int) bool {
		a, b := paths[i], paths[j]
		if a.Risk != b.Risk {
			return a.Risk > b.Risk
		}
		if c := compareNodeSeq(a.Nodes, b.Nodes); c != 0 {
			return c < 0
		}
		return joinSteps(a.Steps) < joinSteps(b.Steps)
	})
}

func normalizeConstraint(c Constraint) Constraint {
	c.Starts = uniqueSorted(c.Starts)
	c.Targets = uniqueSorted(c.Targets)
	c.Required = uniqueSorted(c.Required)
	c.Excluded = uniqueSorted(c.Excluded)
	if len(c.Starts) == 0 {
		c.Starts = []string{InternetID}
	}
	return c
}

// resolveTargets returns critical assets when the caller leaves Targets
// empty.
func resolveTargets(snap *Snapshot, c Constraint) []string {
	if len(c.Targets) > 0 {
		return c.Targets
	}
	var critical []string
	for id, a := range snap.assets {
		if a.Critical {
			critical = append(critical, id)
		}
	}
	sort.Strings(critical)
	return critical
}

func queryPaths(snap *Snapshot, c Constraint) QueryResult {
	if len(c.Starts) == 0 {
		c.Starts = []string{InternetID}
	}
	if len(c.Targets) == 0 {
		c.Targets = resolveTargets(snap, c)
		if len(c.Targets) == 0 {
			return QueryResult{Empty: true, Reason: "no critical assets defined"}
		}
	}
	if err := validateConstraint(snap, c); err != nil {
		return QueryResult{Empty: true, Reason: err.Error()}
	}
	paths := enumeratePaths(snap, c)
	if len(paths) == 0 {
		reason := "no path satisfies the constraint"
		if len(c.Excluded) > 0 || len(c.Required) > 0 || c.MaxLength > 0 {
			reason = "no path within the given required/excluded nodes and length limit"
		}
		return QueryResult{Empty: true, Reason: reason}
	}
	return QueryResult{Paths: paths}
}

func validateConstraint(snap *Snapshot, c Constraint) error {
	known := func(id string) bool {
		return id == InternetID || snap.assets[id].ID != ""
	}
	for _, id := range c.Starts {
		if !known(id) {
			return errors.New("unknown start node: " + id)
		}
	}
	for _, id := range c.Targets {
		if !known(id) {
			return errors.New("unknown target node: " + id)
		}
	}
	for _, id := range c.Required {
		if !known(id) {
			return errors.New("unknown required node: " + id)
		}
	}
	for _, id := range c.Excluded {
		if !known(id) {
			return errors.New("unknown excluded node: " + id)
		}
	}
	return nil
}

func toStringSet(in []string) map[string]bool {
	out := make(map[string]bool, len(in))
	for _, s := range in {
		out[s] = true
	}
	return out
}

func containsAll(nodes []string, required map[string]bool) bool {
	if len(required) == 0 {
		return true
	}
	have := toStringSet(nodes)
	for r := range required {
		if !have[r] {
			return false
		}
	}
	return true
}

func compareNodeSeq(a, b []string) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	}
	return 0
}

func dedupPaths(paths []AttackPath) []AttackPath {
	seen := map[string]bool{}
	out := paths[:0]
	for _, p := range paths {
		key := joinSteps(p.Steps)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, p)
	}
	return out
}

func joinSteps(steps []Step) string {
	var buf []byte
	for i, s := range steps {
		if i > 0 {
			buf = append(buf, '|')
		}
		buf = append(buf, s.From...)
		buf = append(buf, 0)
		buf = append(buf, s.To...)
		buf = append(buf, 0)
		buf = append(buf, s.VulnID...)
	}
	return string(buf)
}

func joinNodes(nodes []string) string {
	var buf []byte
	for i, n := range nodes {
		if i > 0 {
			buf = append(buf, 0)
		}
		buf = append(buf, n...)
	}
	return string(buf)
}
