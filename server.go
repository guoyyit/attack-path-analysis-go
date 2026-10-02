package attackpath

import (
	"encoding/json"
	"net/http"
	"strings"
)

// NewHTTPServer exposes the service over a small JSON HTTP API:
//
//	POST /apply          {"ops":[<op>,...]}
//	POST /query          {"target":..,"start_assets":[..],
//	                      "must_include":[..],"exclude":[..],"max_steps":N}
//	GET  /risk/{assetID}
//	GET  /compromised/{assetID}
//	GET  /healthz
//
// Operations are committed atomically. Query responses are computed from one
// immutable snapshot, so a query racing an update never observes a partial
// write. An empty query result is the JSON value [].
func NewHTTPServer(s *Service) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /apply", func(w http.ResponseWriter, r *http.Request) {
		var req applyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		ops := make([]Op, 0, len(req.Ops))
		for _, in := range req.Ops {
			op, err := in.toOp()
			if err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			ops = append(ops, op)
		}
		if err := s.Apply(ops); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "committed"})
	})
	mux.HandleFunc("POST /query", func(w http.ResponseWriter, r *http.Request) {
		var req queryRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		q := Query{
			Target: req.Target,
			Constraint: Constraint{
				StartAssets: req.StartAssets,
				MustInclude: req.MustInclude,
				Exclude:     req.Exclude,
				MaxSteps:    req.MaxSteps,
			},
		}
		results := s.Query(q)
		writeJSON(w, http.StatusOK, marshalRisks(results))
	})
	mux.HandleFunc("GET /risk/{id}", func(w http.ResponseWriter, r *http.Request) {
		risk := s.Risk(r.PathValue("id"))
		if risk == nil {
			writeJSON(w, http.StatusOK, nil)
			return
		}
		writeJSON(w, http.StatusOK, marshalRisk(risk))
	})
	mux.HandleFunc("GET /compromised/{id}", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]bool{"compromised": s.Compromised(r.PathValue("id"))})
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	return mux
}

type applyRequest struct {
	Ops []wireOp `json:"ops"`
}

type wireOp struct {
	Kind  string     `json:"kind"`
	Asset *wireAsset `json:"asset,omitempty"`
	Rule  *wireRule  `json:"rule,omitempty"`
	Vuln  *wireVuln  `json:"vuln,omitempty"`
}

type wireAsset struct {
	ID         string            `json:"id"`
	Type       string            `json:"type,omitempty"`
	External   bool              `json:"external,omitempty"`
	Critical   bool              `json:"critical,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

type wireRule struct {
	ID           string   `json:"id"`
	From         string   `json:"from"`
	To           string   `json:"to"`
	Capabilities []string `json:"capabilities,omitempty"`
}

type wireVuln struct {
	ID             string   `json:"id"`
	Asset          string   `json:"asset"`
	Exploitability float64  `json:"exploitability"`
	Preconditions  []string `json:"preconditions,omitempty"`
}

type queryRequest struct {
	Target      string   `json:"target"`
	StartAssets []string `json:"start_assets"`
	MustInclude []string `json:"must_include"`
	Exclude     []string `json:"exclude"`
	MaxSteps    int      `json:"max_steps"`
}

func (o wireOp) toOp() (Op, error) {
	switch strings.ToLower(o.Kind) {
	case "upsert_asset":
		if o.Asset == nil {
			return Op{}, errField("asset")
		}
		return Op{Kind: OpUpsertAsset, Asset: &Asset{
			ID: o.Asset.ID, Type: o.Asset.Type, External: o.Asset.External,
			Critical: o.Asset.Critical, Attributes: o.Asset.Attributes,
		}}, nil
	case "delete_asset":
		id := ""
		if o.Asset != nil {
			id = o.Asset.ID
		}
		return Op{Kind: OpDeleteAsset, Asset: &Asset{ID: id}}, nil
	case "upsert_rule":
		if o.Rule == nil {
			return Op{}, errField("rule")
		}
		return Op{Kind: OpUpsertRule, Rule: &ConnectivityRule{
			ID: o.Rule.ID, From: o.Rule.From, To: o.Rule.To, Capabilities: o.Rule.Capabilities,
		}}, nil
	case "delete_rule":
		id := ""
		if o.Rule != nil {
			id = o.Rule.ID
		}
		return Op{Kind: OpDeleteRule, Rule: &ConnectivityRule{ID: id}}, nil
	case "upsert_vuln":
		if o.Vuln == nil {
			return Op{}, errField("vuln")
		}
		return Op{Kind: OpUpsertVuln, Vuln: &Vulnerability{
			ID: o.Vuln.ID, Asset: o.Vuln.Asset,
			Exploitability: o.Vuln.Exploitability,
			Preconditions:  o.Vuln.Preconditions,
		}}, nil
	case "delete_vuln":
		id := ""
		if o.Vuln != nil {
			id = o.Vuln.ID
		}
		return Op{Kind: OpDeleteVuln, Vuln: &Vulnerability{ID: id}}, nil
	default:
		return Op{}, errField("kind")
	}
}

type wireStep struct {
	From        string  `json:"from"`
	To          string  `json:"to"`
	RuleID      string  `json:"rule_id"`
	VulnID      string  `json:"vuln_id"`
	Probability float64 `json:"probability"`
}

type wirePath struct {
	Start       string     `json:"start"`
	Target      string     `json:"target"`
	Steps       []wireStep `json:"steps"`
	Probability float64    `json:"probability"`
}

type wireRisk struct {
	AssetID   string     `json:"asset_id"`
	Score     float64    `json:"score"`
	PathCount int        `json:"path_count"`
	Paths     []wirePath `json:"paths"`
}

func marshalRisks(risks []*AssetRisk) []wireRisk {
	out := make([]wireRisk, 0, len(risks))
	for _, r := range risks {
		out = append(out, marshalRisk(r))
	}
	return out
}

func marshalRisk(r *AssetRisk) wireRisk {
	paths := make([]wirePath, 0, len(r.Paths))
	for _, p := range r.Paths {
		steps := make([]wireStep, 0, len(p.Steps))
		for _, s := range p.Steps {
			steps = append(steps, wireStep{
				From: s.From, To: s.To, RuleID: s.RuleID, VulnID: s.VulnID,
				Probability: s.Probability,
			})
		}
		paths = append(paths, wirePath{
			Start: p.Start, Target: p.Target, Steps: steps, Probability: p.Probability,
		})
	}
	return wireRisk{AssetID: r.AssetID, Score: r.Score, PathCount: r.PathCount, Paths: paths}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func errField(name string) error {
	return &badRequest{msg: "missing or invalid field: " + name}
}

type badRequest struct{ msg string }

func (e *badRequest) Error() string { return e.msg }
