package attackpath

// InternetID is the pseudo asset that represents the external attacker
// located on the internet. Connectivity rules originating from InternetID
// describe inbound exposure.
const InternetID = "@internet"

// ExternalAccessVulnID is the synthetic exploitation recorded for assets
// directly exposed to the internet without a modelled inbound rule.
const ExternalAccessVulnID = "@external-access"

// Asset describes a host, service or data store in the inventory.
type Asset struct {
	// ID is the unique, stable identifier of the asset.
	ID string `json:"id"`
	// Name is a human readable label.
	Name string `json:"name,omitempty"`
	// External marks an asset directly exposed to the internet.
	External bool `json:"external,omitempty"`
	// Critical marks a crown-jewel asset that paths are searched for.
	Critical bool `json:"critical,omitempty"`
	// Grants lists capability tags obtained by compromising the asset.
	Grants []string `json:"grants,omitempty"`
	// Attrs holds arbitrary, order independent asset attributes.
	Attrs map[string]string `json:"attrs,omitempty"`
}

// Vulnerability describes an exploitable weakness hosted on an asset.
type Vulnerability struct {
	// ID is the unique identifier of the vulnerability.
	ID string `json:"id"`
	// AssetID is the asset that runs the vulnerable service.
	AssetID string `json:"asset_id"`
	// Exploitability is the success probability in the range [0, 1].
	Exploitability float64 `json:"exploitability"`
	// Protocol restricts the ingress vector required for exploitation.
	// An empty string matches any protocol.
	Protocol string `json:"protocol,omitempty"`
	// Port restricts the ingress port. Zero matches any port.
	Port int `json:"port,omitempty"`
	// Requires lists capability tags the attacker must already hold.
	Requires []string `json:"requires,omitempty"`
	// Grants lists capability tags yielded by a successful exploitation.
	Grants []string `json:"grants,omitempty"`
}

// ConnectRule describes a directed trust/connectivity relation: a subject
// controlling SrcID may reach DstID over Protocol/Port. SrcID may be
// InternetID to model inbound internet exposure.
type ConnectRule struct {
	SrcID    string `json:"src_id"`
	DstID    string `json:"dst_id"`
	Protocol string `json:"protocol,omitempty"`
	Port     int    `json:"port,omitempty"`
}

// Step is one successful exploitation hop on an attack path.
type Step struct {
	From   string  `json:"from"`
	To     string  `json:"to"`
	VulnID string  `json:"vuln_id"`
	Risk   float64 `json:"risk"`
}

// AttackPath is a simple (loop free) chain of attack steps from a start
// asset (or the internet) to a target asset.
type AttackPath struct {
	Nodes []string `json:"nodes"`
	Steps []Step   `json:"steps"`
	Risk  float64  `json:"risk"`
}

// Constraint expresses a constrained path query.
type Constraint struct {
	// Starts limits path origins. Empty means the internet entries.
	Starts []string `json:"starts,omitempty"`
	// Targets limits path destinations. Empty means critical assets.
	Targets []string `json:"targets,omitempty"`
	// Required lists nodes every returned path must visit.
	Required []string `json:"required,omitempty"`
	// Excluded lists nodes no returned path may visit.
	Excluded []string `json:"excluded,omitempty"`
	// MaxLength bounds the number of steps. Zero means the engine default.
	MaxLength int `json:"max_length,omitempty"`
}

// QueryResult is the deterministic outcome of a constrained query.
type QueryResult struct {
	// Paths are ordered by descending risk, then lexicographically.
	Paths []AttackPath `json:"paths"`
	// Empty is true when the constraint admits no path.
	Empty bool `json:"empty"`
	// Reason explains why an empty result was produced.
	Reason string `json:"reason,omitempty"`
}

// AssetRisk aggregates every discovered path towards one asset.
type AssetRisk struct {
	AssetID   string       `json:"asset_id"`
	Reachable bool         `json:"reachable"`
	Paths     []AttackPath `json:"paths"`
	// Score aggregates the path risks into an overall compromise score.
	Score float64 `json:"score"`
}

// Report is the full risk view of one consistent snapshot.
type Report struct {
	// Version uniquely identifies the snapshot.
	Version int64 `json:"version"`
	// Entries are the assets reachable directly from the internet.
	Entries []string `json:"entries"`
	// Reachable lists every asset an external attacker can compromise.
	Reachable []string `json:"reachable"`
	// Risks holds one entry per asset, keyed by asset ID.
	Risks map[string]*AssetRisk `json:"risks"`
}

// ChangeSet is an atomic batch of inventory mutations.
// Upserts and deletes inside one batch commit together or not at all.
type ChangeSet struct {
	UpsertAssets []Asset         `json:"upsert_assets,omitempty"`
	DeleteAssets []string        `json:"delete_assets,omitempty"`
	UpsertVulns  []Vulnerability `json:"upsert_vulns,omitempty"`
	DeleteVulns  []string        `json:"delete_vulns,omitempty"`
	UpsertRules  []ConnectRule   `json:"upsert_rules,omitempty"`
	DeleteRules  []ConnectRule   `json:"delete_rules,omitempty"`
}
