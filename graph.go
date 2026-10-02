package attackpath

import (
	"fmt"
	"sort"
)

// graph is an immutable snapshot of the attack model. Readers hold a pointer
// to one snapshot; updates build a new snapshot and atomically swap it.
type graph struct {
	assets map[string]*Asset
	rules  map[string]*ConnectivityRule
	vulns  map[string]*Vulnerability

	// ruleIndex maps asset id -> rules with that source asset.
	ruleIndex map[string][]*ConnectivityRule
	// vulnIndex maps asset id -> vulnerabilities on that asset.
	vulnIndex map[string][]*Vulnerability

	// compromised[id] is true once the attacker can control the asset.
	compromised map[string]bool

	// risks holds the fully aggregated per-asset risk for this snapshot.
	risks map[string]*AssetRisk

	// version strictly increases on every committed swap.
	version uint64
}

// ErrInvalidInput reports a mutation that references unknown data or carries
// an out-of-range value. The whole batch is rejected atomically.
var ErrInvalidInput = fmt.Errorf("invalid input")

// canExploit reports whether vuln can be exploited over rule: the
// vulnerability must live on the rule destination and every precondition must
// be supplied by the rule's capabilities.
func canExploit(rule *ConnectivityRule, vuln *Vulnerability) bool {
	if rule.To != vuln.Asset {
		return false
	}
	caps := rule.Capabilities
	if len(caps) == 0 {
		caps = []string{"network"}
	}
	have := make(map[string]bool, len(caps))
	for _, c := range caps {
		have[c] = true
	}
	for _, need := range vuln.Preconditions {
		if !have[need] {
			return false
		}
	}
	return true
}

// newGraph builds a snapshot from raw data and derives reachability and risk.
func newGraph(version uint64, assets map[string]*Asset, rules map[string]*ConnectivityRule, vulns map[string]*Vulnerability) *graph {
	g := &graph{
		assets:    make(map[string]*Asset, len(assets)),
		rules:     make(map[string]*ConnectivityRule, len(rules)),
		vulns:     make(map[string]*Vulnerability, len(vulns)),
		ruleIndex: map[string][]*ConnectivityRule{},
		vulnIndex: map[string][]*Vulnerability{},
		risks:     map[string]*AssetRisk{},
		version:   version,
	}
	for _, a := range assets {
		g.assets[a.ID] = cloneAsset(a)
	}
	for _, r := range rules {
		r = cloneRule(r)
		g.rules[r.ID] = r
		g.ruleIndex[r.From] = append(g.ruleIndex[r.From], r)
	}
	for _, v := range vulns {
		v = cloneVuln(v)
		g.vulns[v.ID] = v
		g.vulnIndex[v.Asset] = append(g.vulnIndex[v.Asset], v)
	}
	for _, rs := range g.ruleIndex {
		sort.Slice(rs, func(i, j int) bool { return rs[i].ID < rs[j].ID })
	}
	for _, vs := range g.vulnIndex {
		sort.Slice(vs, func(i, j int) bool { return vs[i].ID < vs[j].ID })
	}

	g.compromised = deriveCompromised(g)

	var starts []string
	for id, a := range g.assets {
		if a.External {
			starts = append(starts, id)
		}
	}
	sort.Strings(starts)
	ids := make([]string, 0, len(g.assets))
	for id := range g.assets {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if !g.compromised[id] {
			continue
		}
		if g.assets[id].External {
			g.risks[id] = &AssetRisk{AssetID: id, Score: 1}
			continue
		}
		paths := enumeratePaths(g, starts, id, Constraint{})
		if len(paths) > 0 {
			g.risks[id] = scoreRisk(g, id, paths)
		}
	}
	return g
}

// rebuild returns an equal snapshot rebuilt from scratch at a new version.
func (g *graph) rebuild(version uint64) *graph {
	return newGraph(version, g.assets, g.rules, g.vulns)
}

// apply applies the given mutations and re-derives only affected results.
func (g *graph) apply(version uint64, ops []Op) (*graph, error) {
	assets := make(map[string]*Asset, len(g.assets))
	for id, a := range g.assets {
		assets[id] = a
	}
	rules := make(map[string]*ConnectivityRule, len(g.rules))
	for id, r := range g.rules {
		rules[id] = r
	}
	vulns := make(map[string]*Vulnerability, len(g.vulns))
	for id, v := range g.vulns {
		vulns[id] = v
	}

	seeds := map[string]bool{}
	for _, op := range ops {
		switch op.Kind {
		case OpUpsertAsset:
			if op.Asset == nil || op.Asset.ID == "" {
				return nil, fmt.Errorf("%w: asset requires an id", ErrInvalidInput)
			}
			assets[op.Asset.ID] = cloneAsset(op.Asset)
			seeds[op.Asset.ID] = true
		case OpDeleteAsset:
			if op.Asset == nil || op.Asset.ID == "" {
				return nil, fmt.Errorf("%w: asset deletion requires an id", ErrInvalidInput)
			}
			id := op.Asset.ID
			if _, ok := assets[id]; !ok {
				continue
			}
			seeds[id] = true
			for _, r := range g.ruleIndex[id] {
				seeds[r.To] = true
				delete(rules, r.ID)
			}
			for _, r := range g.rules {
				if r.To == id {
					seeds[r.From] = true
					delete(rules, r.ID)
				}
			}
			for _, v := range g.vulnIndex[id] {
				delete(vulns, v.ID)
			}
			delete(assets, id)
		case OpUpsertRule:
			if op.Rule == nil || op.Rule.ID == "" || op.Rule.From == "" || op.Rule.To == "" {
				return nil, fmt.Errorf("%w: rule requires id, from and to", ErrInvalidInput)
			}
			if _, ok := assets[op.Rule.From]; !ok {
				return nil, fmt.Errorf("%w: rule %q references unknown source asset %q", ErrInvalidInput, op.Rule.ID, op.Rule.From)
			}
			if _, ok := assets[op.Rule.To]; !ok {
				return nil, fmt.Errorf("%w: rule %q references unknown destination asset %q", ErrInvalidInput, op.Rule.ID, op.Rule.To)
			}
			if old := rules[op.Rule.ID]; old != nil {
				seeds[old.From] = true
				seeds[old.To] = true
			}
			r := cloneRule(op.Rule)
			rules[r.ID] = r
			seeds[r.From] = true
			seeds[r.To] = true
		case OpDeleteRule:
			if op.Rule == nil || op.Rule.ID == "" {
				return nil, fmt.Errorf("%w: rule deletion requires an id", ErrInvalidInput)
			}
			if old := rules[op.Rule.ID]; old != nil {
				seeds[old.From] = true
				seeds[old.To] = true
				delete(rules, old.ID)
			}
		case OpUpsertVuln:
			if op.Vuln == nil || op.Vuln.ID == "" || op.Vuln.Asset == "" {
				return nil, fmt.Errorf("%w: vulnerability requires id and asset", ErrInvalidInput)
			}
			if op.Vuln.Exploitability < 0 || op.Vuln.Exploitability > 1 {
				return nil, fmt.Errorf("%w: vulnerability %q exploitability must be in [0,1]", ErrInvalidInput, op.Vuln.ID)
			}
			if _, ok := assets[op.Vuln.Asset]; !ok {
				return nil, fmt.Errorf("%w: vulnerability %q references unknown asset %q", ErrInvalidInput, op.Vuln.ID, op.Vuln.Asset)
			}
			if old := vulns[op.Vuln.ID]; old != nil {
				seeds[old.Asset] = true
			}
			v := cloneVuln(op.Vuln)
			vulns[v.ID] = v
			seeds[v.Asset] = true
		case OpDeleteVuln:
			if op.Vuln == nil || op.Vuln.ID == "" {
				return nil, fmt.Errorf("%w: vulnerability deletion requires an id", ErrInvalidInput)
			}
			if old := vulns[op.Vuln.ID]; old != nil {
				seeds[old.Asset] = true
				delete(vulns, old.ID)
			}
		default:
			return nil, fmt.Errorf("%w: unknown op kind %d", ErrInvalidInput, op.Kind)
		}
	}

	ng := newDerivedGraph(version, assets, rules, vulns)
	region := affectedRegion(g, ng, seeds)

	ng.compromised = make(map[string]bool, len(g.compromised))
	for id, c := range g.compromised {
		if _, alive := ng.assets[id]; alive && !region[id] {
			ng.compromised[id] = c
		}
	}
	ng.risks = make(map[string]*AssetRisk, len(g.risks))
	for id, r := range g.risks {
		if _, alive := ng.assets[id]; alive && !region[id] {
			ng.risks[id] = r
		}
	}
	rederiveRegion(ng, region)
	return ng, nil
}

// query enumerates and scores paths matching q.
func (g *graph) query(q Query) []*AssetRisk {
	var starts []string
	if len(q.StartAssets) > 0 {
		seen := map[string]bool{}
		for _, id := range q.StartAssets {
			if _, ok := g.assets[id]; ok && !seen[id] {
				seen[id] = true
				starts = append(starts, id)
			}
		}
		sort.Strings(starts)
	} else {
		for id, a := range g.assets {
			if a.External {
				starts = append(starts, id)
			}
		}
		sort.Strings(starts)
	}

	var targets []string
	if q.Target != "" {
		if _, ok := g.assets[q.Target]; ok {
			targets = []string{q.Target}
		}
	} else {
		for id, a := range g.assets {
			if a.Critical {
				targets = append(targets, id)
			}
		}
		sort.Strings(targets)
	}

	excluded := map[string]bool{}
	for _, id := range q.Exclude {
		excluded[id] = true
	}

	out := []*AssetRisk{}
	for _, target := range targets {
		if excluded[target] {
			continue
		}
		paths := enumeratePaths(g, starts, target, q.Constraint)
		if len(paths) == 0 {
			continue
		}
		out = append(out, scoreRisk(g, target, paths))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].AssetID < out[j].AssetID
	})
	return out
}

func cloneAsset(a *Asset) *Asset {
	cp := *a
	if a.Attributes != nil {
		cp.Attributes = make(map[string]string, len(a.Attributes))
		for k, v := range a.Attributes {
			cp.Attributes[k] = v
		}
	}
	return &cp
}

func cloneRule(r *ConnectivityRule) *ConnectivityRule {
	cp := *r
	if r.Capabilities != nil {
		cp.Capabilities = append([]string(nil), r.Capabilities...)
		sort.Strings(cp.Capabilities)
	}
	return &cp
}

func cloneVuln(v *Vulnerability) *Vulnerability {
	cp := *v
	if v.Preconditions != nil {
		cp.Preconditions = append([]string(nil), v.Preconditions...)
		sort.Strings(cp.Preconditions)
	}
	return &cp
}

// newDerivedGraph builds the indexed structure of a new snapshot without
// running the reachability fixpoint or risk scoring.
func newDerivedGraph(version uint64, assets map[string]*Asset, rules map[string]*ConnectivityRule, vulns map[string]*Vulnerability) *graph {
	g := &graph{
		assets:    assets,
		rules:     rules,
		vulns:     vulns,
		ruleIndex: map[string][]*ConnectivityRule{},
		vulnIndex: map[string][]*Vulnerability{},
		risks:     map[string]*AssetRisk{},
		version:   version,
	}
	for _, r := range rules {
		g.ruleIndex[r.From] = append(g.ruleIndex[r.From], r)
	}
	for _, rs := range g.ruleIndex {
		sort.Slice(rs, func(i, j int) bool { return rs[i].ID < rs[j].ID })
	}
	for _, v := range vulns {
		g.vulnIndex[v.Asset] = append(g.vulnIndex[v.Asset], v)
	}
	for _, vs := range g.vulnIndex {
		sort.Slice(vs, func(i, j int) bool { return vs[i].ID < vs[j].ID })
	}
	return g
}
