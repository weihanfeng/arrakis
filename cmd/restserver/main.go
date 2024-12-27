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
	"github.com/spf13/viper"
	"github.com/urfave/cli/v2"

	"github.com/abshkbh/chv-lambda/out/gen/serverapi"
	"github.com/abshkbh/chv-lambda/pkg/config"
	"github.com/abshkbh/chv-lambda/pkg/server"
)

const (
	defaultStateDir     = "/run/chv-lambda"
	defaultBridgeName   = "br0"
	defaultBridgeIP     = "10.20.1.1/24"
	defaultBridgeSubnet = "10.20.1.0/24"
	defaultChvBinPath   = "resources/bin/cloud-hypervisor"
	defaultKernelPath   = "resources/bin/vmlinux.bin"
)

type restServer struct {
	vmServer *server.Server
}

// Implement handler functions
func (s *restServer) startVM(w http.ResponseWriter, r *http.Request) {
	var req serverapi.StartVMRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	if req.GetVmName() == "" {
		http.Error(w, "Empty vm name", http.StatusBadRequest)
		return
	}

	if req.GetKernel() == "" {
		http.Error(w, "Empty kernel", http.StatusBadRequest)
		return
	}

	if req.GetRootfs() == "" {
		http.Error(w, "Empty rootfs", http.StatusBadRequest)
		return
	}

	resp, err := s.vmServer.StartVM(r.Context(), &req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to start VM: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *restServer) stopVM(w http.ResponseWriter, r *http.Request) {
	var req serverapi.VMRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	resp, err := s.vmServer.StopVM(r.Context(), &req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to stop VM: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *restServer) destroyVM(w http.ResponseWriter, r *http.Request) {
	var req serverapi.VMRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Invalid request body: %v", err), http.StatusBadRequest)
		return
	}

	resp, err := s.vmServer.DestroyVM(r.Context(), &req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to destroy VM: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *restServer) destroyAllVMs(w http.ResponseWriter, r *http.Request) {
	resp, err := s.vmServer.DestroyAllVMs(r.Context())
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to destroy all VMs: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *restServer) listAllVMs(w http.ResponseWriter, r *http.Request) {
	resp, err := s.vmServer.ListAllVMs(r.Context())
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to list all VMs: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *restServer) listVM(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	vmName := vars["name"]
	resp, err := s.vmServer.ListVM(r.Context(), vmName)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to list VM: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func setConfigParsing() {
	viper.SetDefault(
		"restserver.chv_bin",
		defaultChvBinPath,
	)
	viper.SetDefault(
		"restserver.kernel",
		defaultKernelPath,
	)
	viper.SetDefault(
		"restserver.state_dir",
		defaultStateDir,
	)
	viper.SetDefault(
		"restserver.bridge_name",
		defaultBridgeName,
	)
	viper.SetDefault(
		"restserver.bridge_ip",
		defaultBridgeIP,
	)
	viper.SetDefault(
		"restserver.bridge_subnet",
		defaultBridgeSubnet,
	)
}

func main() {
	var serverConfig server.ServerConfig
	var configFile string

	app := &cli.App{
		Name:  "chv-restserver",
		Usage: "A daemon for spawning and managing cloud-hypervisor based microVMs.",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "config",
				Aliases:     []string{"c"},
				Required:    true,
				Usage:       "Path to config file",
				Destination: &configFile,
			},
		},
		Action: func(ctx *cli.Context) error {
			file, err := os.Open(configFile)
			if err != nil {
				return fmt.Errorf("failed to open config file: %s err: %v", configFile, err)
			}
			defer file.Close()

			setConfigParsing()
			err = viper.ReadConfig(file)
			if err != nil {
				return fmt.Errorf("failed to read config: %v", err)
			}

			restServerConfig := viper.Sub("restserver")
			if restServerConfig == nil {
				return fmt.Errorf("restserver configuration not found")
			}

			if err := restServerConfig.Unmarshal(&serverConfig); err != nil {
				return fmt.Errorf("error unmarshalling config: %v", err)
			}
			log.Infof("server config: %v", serverConfig)
			return nil
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.WithError(err).Fatal("server exited with error")
	}

	// At this point `serverConfig` is populated.
	// Create the VM server
	vmServer, err := server.NewServer(serverConfig)
	if err != nil {
		log.Fatalf("failed to create VM server: %v", err)
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
	vmServer.DestroyAllVMs(context.Background())
	log.Println("Server stopped")
}
