// Command apasvc runs the local attack path analysis service over HTTP.
//
// Endpoints:
//
//	GET  /health            liveness probe
//	GET  /snapshot          current snapshot version and summary
//	GET  /report            full risk report of the committed snapshot
//	POST /query             constrained path query, body: Constraint JSON
//	POST /updates           atomically apply one ChangeSet JSON batch
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"

	"github.com/guoyyit/attack-path-analysis-go"
)

func main() {
	addr := flag.String("addr", envOr("APA_ADDR", "127.0.0.1:8080"), "listen address")
	dir := flag.String("data", envOr("APA_DATA", ""), "persistence directory (empty = in memory)")
	flag.Parse()

	svc, err := attackpath.Open(*dir)
	if err != nil {
		log.Fatalf("open service: %v", err)
	}
	defer svc.Close()

	mux := buildMux(svc)
	log.Printf("attack path analysis service listening on %s (data=%q)", *addr, *dir)
	if err := http.ListenAndServe(*addr, mux); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func buildMux(svc *attackpath.Service) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("/snapshot", func(w http.ResponseWriter, r *http.Request) {
		snap := svc.Current()
		writeJSON(w, http.StatusOK, map[string]any{
			"version":   snap.Version(),
			"entries":   snap.Entries(),
			"reachable": snap.Reachable(),
		})
	})
	mux.HandleFunc("/report", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, svc.Report())
	})
	mux.HandleFunc("/query", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "use POST"})
			return
		}
		var c attackpath.Constraint
		if err := decodeJSON(r, &c); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, svc.Query(c))
	})
	mux.HandleFunc("/updates", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "use POST"})
			return
		}
		var cs attackpath.ChangeSet
		if err := decodeJSON(r, &cs); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if err := svc.Update(cs); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"version": svc.Current().Version()})
	})
	return mux
}

func decodeJSON(r *http.Request, v any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
