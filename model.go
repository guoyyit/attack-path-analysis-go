// Package attackpath implements a local attack-path analysis service.
//
// It builds an attack graph from an asset inventory, connectivity rules
// (trust relationships) and vulnerability advisories, derives the assets an
// attacker can compromise starting from external entry points, enumerates
// attack paths to critical assets and scores their risk.
package attackpath

// Asset is a node in the attack graph.
//
// External assets are attacker-controlled entry points. Critical assets are
// the protected targets ("key assets"). Attributes carry arbitrary
// asset-specific properties and participate in change detection.
type Asset struct {
	ID         string
	Type       string
	External   bool
	Critical   bool
	Attributes map[string]string
}

// ConnectivityRule is a directed trust edge From -> To.
//
// Capabilities describe what an attacker who controls From gains towards To,
// e.g. "network" reachability or "credential:ssh-key". A vulnerability whose
// preconditions are a subset of these capabilities can be exploited over the
// rule. Capabilities defaults to ["network"] when empty.
type ConnectivityRule struct {
	ID           string
	From         string
	To           string
	Capabilities []string
}

// Vulnerability is attached to an asset and may be exploited to compromise it.
//
// Exploitability is the independent success probability in [0,1] of the
// exploit step. Preconditions list the capabilities that must all be provided
// by the connectivity rule over which the attacker arrives.
type Vulnerability struct {
	ID             string
	Asset          string
	Exploitability float64
	Preconditions  []string
}

// Step is one exploitation hop on an attack path.
type Step struct {
	From        string
	To          string
	RuleID      string
	VulnID      string
	Probability float64
}

// AttackPath is a simple (asset-acyclic) sequence of steps from an entry
// asset to a target asset.
type AttackPath struct {
	Start       string
	Target      string
	Steps       []Step
	Probability float64
}

// Constraint restricts a path query.
//
// StartAssets limits the allowed entry points (empty = all external assets).
// MustInclude requires every listed asset to appear on the path. Exclude
// removes paths touching any listed asset. MaxSteps caps the number of steps;
// zero means unlimited (enumeration is always bounded by the asset count).
type Constraint struct {
	StartAssets []string
	MustInclude []string
	Exclude     []string
	MaxSteps    int
}

// Query selects paths to one target (empty = every critical asset).
type Query struct {
	Target string
	Constraint
}

// AssetRisk aggregates every path that reaches an asset.
type AssetRisk struct {
	AssetID   string
	Score     float64
	PathCount int
	Paths     []AttackPath
}

// OpKind identifies a single mutation inside a transaction.
type OpKind int

const (
	OpUpsertAsset OpKind = iota + 1
	OpDeleteAsset
	OpUpsertRule
	OpDeleteRule
	OpUpsertVuln
	OpDeleteVuln
)

// Op is one mutation. Only the field matching Kind is consulted.
type Op struct {
	Kind  OpKind
	Asset *Asset
	Rule  *ConnectivityRule
	Vuln  *Vulnerability
}
