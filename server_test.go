package attackpath

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestServer(t *testing.T) (*Service, http.Handler) {
	t.Helper()
	s := NewService()
	return s, NewHTTPServer(s)
}

func doJSON(t *testing.T, h http.Handler, method, path string, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]any
	if rec.Body.Len() > 0 && rec.Body.String() != "null" {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode %s: %v body=%q", path, err, rec.Body.String())
		}
	}
	return rec.Code, out
}

func TestHTTPEndToEnd(t *testing.T) {
	s, h := newTestServer(t)

	code, out := doJSON(t, h, "POST", "/apply", `{
	  "ops":[
	    {"kind":"upsert_asset","asset":{"id":"e","external":true}},
	    {"kind":"upsert_asset","asset":{"id":"k","critical":true}},
	    {"kind":"upsert_rule","rule":{"id":"r","from":"e","to":"k"}},
	    {"kind":"upsert_vuln","vuln":{"id":"v","asset":"k","exploitability":0.5}}
	  ]}`)
	if code != http.StatusOK || out["status"] != "committed" {
		t.Fatalf("apply failed: %d %v", code, out)
	}

	// Query with an explicit target.
	req := httptest.NewRequest("POST", "/query", strings.NewReader(`{"target":"k"}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var rows []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0]["asset_id"] != "k" {
		t.Fatalf("unexpected query rows: %v", rows)
	}
	if score, _ := rows[0]["score"].(float64); !approx(score, 0.5) {
		t.Fatalf("unexpected score: %v", rows[0])
	}

	// Empty result is an explicit JSON [].
	req = httptest.NewRequest("POST", "/query", strings.NewReader(`{"target":"k","exclude":["k"]}`))
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Fatalf("expected [], got %q", rec.Body.String())
	}

	// Single asset risk + compromise lookups.
	code, out = doJSON(t, h, "GET", "/risk/k", "")
	if code != 200 || out["score"].(float64) != 0.5 {
		t.Fatalf("risk endpoint: %d %v", code, out)
	}
	code, out = doJSON(t, h, "GET", "/compromised/k", "")
	if code != 200 || out["compromised"] != true {
		t.Fatalf("compromised endpoint: %d %v", code, out)
	}

	// Invalid batch is rejected with a 4xx and leaves state untouched.
	code, out = doJSON(t, h, "POST", "/apply", `{
	  "ops":[{"kind":"upsert_rule","rule":{"id":"x","from":"e","to":"ghost"}}]}`)
	if code == http.StatusOK {
		t.Fatalf("expected client error, got %d", code)
	}
	if got := s.Risk("k"); got == nil || !approx(got.Score, 0.5) {
		t.Fatalf("state changed after rejected batch: %+v", got)
	}

	if req := httptest.NewRequest("GET", "/healthz", nil); req != nil {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != 200 || rec.Body.String() != "ok" {
			t.Fatalf("healthz: %d %q", rec.Code, rec.Body.String())
		}
	}
}
