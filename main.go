package main

import (
	"fmt"
	"log"
	"net/http"
	"sync/atomic"
)

type apiConfig struct {
	fileServerHits atomic.Int32
}

// Keeping track the number of times a handler has been called
func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		cfg.fileServerHits.Add(1)
		next.ServeHTTP(w, req)
	})
}

func healthHandler(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("content-type", "text/plain; charset=utf-8")
		w.WriteHeader(200)
		w.Write([]byte("OK"))
}

func (cfg *apiConfig) metricsHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("content-type", "text/plain")
	w.WriteHeader(200)
	w.Write(fmt.Appendf([]byte{}, "Hits: %d", cfg.fileServerHits.Load()))
}

func (cfg *apiConfig) resetMetricsHandler(w http.ResponseWriter, req *http.Request) {
	cfg.fileServerHits.Store(0)
	w.Header().Set("content-type", "text/plain")
	w.WriteHeader(200)
	w.Write([]byte("Counter reset to 0!"))
}

func main() {
	mux := http.NewServeMux()
	handler := http.StripPrefix("/app/", http.FileServer(http.Dir(".")))
	apiCfg := apiConfig{}
	mux.Handle("/app/", apiCfg.middlewareMetricsInc(handler))
	server := http.Server{ Handler: mux, Addr: ":8080" }

	mux.HandleFunc("GET /api/healthz", healthHandler)
	mux.HandleFunc("GET /api/metrics", apiCfg.metricsHandler)
	mux.HandleFunc("POST /api/reset", apiCfg.resetMetricsHandler)

	log.Print("Running server")
	server.ListenAndServe()
}
