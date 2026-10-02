package attackpath

import "sort"

// pathScore combines the exploitability of the steps of one path.
func pathScore(steps []Step) float64 {
	score := 1.0
	for _, s := range steps {
		score *= s.Risk
	}
	return score
}

// aggregateScore combines independent path risks into one asset score:
// 1 - product(1 - p_i). The input is sorted to stay input-order independent.
func aggregateScore(paths []AttackPath) float64 {
	// Sort to guarantee the floating-point product is input-order
	// independent; risks are canonicalised before aggregation upstream.
	probs := make([]float64, 0, len(paths))
	for _, p := range paths {
		probs = append(probs, p.Risk)
	}
	sort.Float64s(probs)
	alive := 1.0
	for _, p := range probs {
		alive *= 1 - p
	}
	return 1 - alive
}

// buildReport assembles the full risk report for a snapshot.
func buildReport(snap *Snapshot) *Report {
	risks := map[string]*AssetRisk{}
	pathsByTarget := map[string][]AttackPath{}

	for _, targetID := range sortedAssetIDs(snap.reached) {
		paths := enumeratePaths(snap, Constraint{
			Starts:    []string{InternetID},
			Targets:   []string{targetID},
			MaxLength: 0,
		})
		if len(paths) == 0 {
			continue
		}
		pathsByTarget[targetID] = paths
	}

	targetIDs := make([]string, 0, len(pathsByTarget))
	for id := range pathsByTarget {
		targetIDs = append(targetIDs, id)
	}
	sort.Strings(targetIDs)
	for _, id := range targetIDs {
		paths := pathsByTarget[id]
		risks[id] = &AssetRisk{
			AssetID:   id,
			Reachable: true,
			Paths:     paths,
			Score:     aggregateScore(paths),
		}
	}

	reachable := sortedAssetIDs(snap.reached)
	return &Report{
		Version:   snap.version,
		Entries:   append([]string(nil), snap.entries...),
		Reachable: reachable,
		Risks:     risks,
	}
}
