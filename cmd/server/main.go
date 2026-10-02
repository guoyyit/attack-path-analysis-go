// Command attackpathd runs the local attack-path analysis HTTP service.
//
// Usage:
//
//	attackpathd [-addr :8080] [-data ./data]
//
// All committed data is persisted in -data and recovered on restart.
package main

import (
	"flag"
	"log"
	"net/http"

	attackpath "github.com/guoyyit/attack-path-analysis-go"
)

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	dataDir := flag.String("data", "./data", "persistence directory (WAL)")
	flag.Parse()

	svc, err := attackpath.Open(*dataDir)
	if err != nil {
		log.Fatalf("open: %v", err)
	}
	defer svc.Close()

	log.Printf("attack-path analysis service listening on %s (data=%s)", *addr, *dataDir)
	if err := http.ListenAndServe(*addr, attackpath.NewHTTPServer(svc)); err != nil {
		log.Fatal(err)
	}
}
