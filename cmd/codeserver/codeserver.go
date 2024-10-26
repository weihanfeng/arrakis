package main

import (
	"encoding/json"
	"net/http"

	log "github.com/sirupsen/logrus"
)

type codeServer struct {
}

func (cs *codeServer) indexRoute(w http.ResponseWriter, r *http.Request) {
	response := map[string]string{
		"msg": "Hello from codeserver",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func initializeRoutes(cs *codeServer) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", cs.indexRoute)
	return mux
}

func main() {
	log.Info("starting codeserver...")
	cs := &codeServer{}
	router := initializeRoutes(cs)

	server := &http.Server{
		Addr:    ":8080",
		Handler: router,
	}

	err := server.ListenAndServe()
	if err != nil {
		log.WithError(err).Error("codeserver exited with: %v", err)
	}
}
