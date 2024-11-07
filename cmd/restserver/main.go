package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"

	"github.com/abshkbh/chv-lambda/out/protos"
	"github.com/abshkbh/chv-lambda/pkg/config"
	"github.com/abshkbh/chv-lambda/pkg/server"
)

type restServer struct {
	vmServer *server.Server
}

// Implement handler functions
func (s *restServer) startVM(w http.ResponseWriter, r *http.Request) {
	var req protos.StartVMRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	resp, err := s.vmServer.StartVM(r.Context(), &req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to start VM: %v", err), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(resp)
}

func (s *restServer) stopVM(w http.ResponseWriter, r *http.Request) {
	var req protos.VMRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	resp, err := s.vmServer.StopVM(r.Context(), &req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to stop VM: %v", err), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(resp)
}

func (s *restServer) destroyVM(w http.ResponseWriter, r *http.Request) {
	var req protos.VMRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	resp, err := s.vmServer.DestroyVM(r.Context(), &req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to destroy VM: %v", err), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(resp)
}

func (s *restServer) destroyAllVMs(w http.ResponseWriter, r *http.Request) {
	req := &protos.DestroyAllVMsRequest{}
	resp, err := s.vmServer.DestroyAllVMs(r.Context(), req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to destroy all VMs: %v", err), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(resp)
}

func (s *restServer) listAllVMs(w http.ResponseWriter, r *http.Request) {
	req := &protos.ListAllVMsRequest{}
	resp, err := s.vmServer.ListAllVMs(r.Context(), req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to list all VMs: %v", err), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(resp)
}

func (s *restServer) listVM(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	vmName := vars["name"]

	req := &protos.ListVMRequest{VmName: vmName}
	resp, err := s.vmServer.ListVM(r.Context(), req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to list VM: %v", err), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(resp)
}

func main() {
	// Create the VM server
	vmServer, err := server.NewServer(config.StateDir, config.BridgeName, config.BridgeIP, config.BridgeSubnet)
	if err != nil {
		log.Fatalf("Failed to create VM server: %v", err)
	}

	// Create REST server
	s := &restServer{vmServer: vmServer}
	r := mux.NewRouter()

	// Register routes
	r.HandleFunc("/vm/start", s.startVM).Methods("POST")
	r.HandleFunc("/vm/stop", s.stopVM).Methods("POST")
	r.HandleFunc("/vm/destroy", s.destroyVM).Methods("POST")
	r.HandleFunc("/vm/destroy-all", s.destroyAllVMs).Methods("POST")
	r.HandleFunc("/vm/list", s.listAllVMs).Methods("GET")
	r.HandleFunc("/vm/{name}", s.listVM).Methods("GET")

	// Start HTTP server
	srv := &http.Server{
		Addr:    config.RestServerAddr + ":" + config.RestServerPort,
		Handler: r,
	}

	go func() {
		log.Printf("REST server listening on: %s:%s", config.RestServerAddr, config.RestServerPort)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down server...")
	if err := srv.Shutdown(context.Background()); err != nil {
		log.Fatalf("Server shutdown failed: %v", err)
	}
	vmServer.DestroyAllVMs(context.Background(), &protos.DestroyAllVMsRequest{})
	log.Println("Server stopped")
}
