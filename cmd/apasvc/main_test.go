package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/guoyyit/attack-path-analysis-go"
)

func TestHTTPEndToEnd(t *testing.T) {
	dir := t.TempDir()
	svc, err := attackpath.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()

	mux := buildMux(svc)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	batch := attackpath.ChangeSet{
		UpsertAssets: []attackpath.Asset{
			{ID: "web", External: true, Grants: []string{"k"}},
			{ID: "db", Critical: true},
		},
		UpsertVulns: []attackpath.Vulnerability{
			{ID: "v1", AssetID: "web", Exploitability: 0.7},
			{ID: "v2", AssetID: "db", Exploitability: 0.4, Requires: []string{"k"}},
		},
		UpsertRules: []attackpath.ConnectRule{
			{SrcID: attackpath.InternetID, DstID: "web"},
			{SrcID: "web", DstID: "db"},
		},
	}
	body, _ := json.Marshal(batch)
	resp, err := http.Post(ts.URL+"/updates", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("updates status = %d", resp.StatusCode)
	}
	resp.Body.Close()

	qbody := strings.NewReader(`{"max_length":5}`)
	resp, err = http.Post(ts.URL+"/query", "application/json", qbody)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var qr attackpath.QueryResult
	if err := json.NewDecoder(resp.Body).Decode(&qr); err != nil {
		t.Fatal(err)
	}
	if qr.Empty || len(qr.Paths) != 1 {
		t.Fatalf("expected one path, got %+v", qr)
	}

	resp, err = http.Get(ts.URL + "/report")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var rep attackpath.Report
	if err := json.NewDecoder(resp.Body).Decode(&rep); err != nil {
		t.Fatal(err)
	}
	if rep.Version != 1 || rep.Risks["db"] == nil {
		t.Fatalf("bad report: %+v", rep)
	}

	// Reopen: persistence round trip through HTTP service state.
	svc.Close()
	svc2, err := attackpath.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if svc2.Current().Version() != 1 {
		t.Fatalf("reopened version = %d", svc2.Current().Version())
	}
	svc2.Close()
}
