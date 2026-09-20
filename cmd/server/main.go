package main

import (
	"flag"
	"log"
	"net/http"

	"zonesim/internal/api"
	"zonesim/internal/service"
	"zonesim/internal/store"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:5205", "listen address")
	dataDir := flag.String("data", "./data", "persistent data directory")
	flag.Parse()

	st, err := store.New(*dataDir)
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	svc := service.New(st)
	h := api.New(svc, api.UI())

	log.Printf("zone cutover simulator listening on http://%s (data=%s)", *listen, *dataDir)
	srv := &http.Server{Addr: *listen, Handler: h}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
