// Command server runs the zone release simulator HTTP service and browser UI.
package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"zonesim/internal/api"
	"zonesim/internal/service"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:5205", "address to listen on")
	dataDir := flag.String("data", envOr("ZONESIM_DATA", filepath.Join(os.TempDir(), "zonesim-data")), "data directory")
	flag.Parse()

	svc, err := service.New(*dataDir)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	handler := api.New(svc)
	log.Printf("zone release simulator listening on http://%s (data: %s)", *listen, *dataDir)
	srv := &http.Server{Addr: *listen, Handler: handler}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
