package main

import (
	"context"
	"fmt"
	"net"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/abshkbh/chv-lambda/out/protos"
	"google.golang.org/grpc"
)

const (
	vmStatePath = "/run/chv-lambda"
)

type server struct {
	protos.UnimplementedVMManagementServiceServer
}

func (s *server) StartVM(ctx context.Context, req *protos.VMRequest) (*protos.VMResponse, error) {
	log.Printf("Received request to start VM: %v", req.GetVmName())
	// Implement your VM start logic here
	return &protos.VMResponse{
		Success: true,
		Message: fmt.Sprintf("VM %s started successfully", req.GetVmName()),
	}, nil
}

func (s *server) StopVM(ctx context.Context, req *protos.VMRequest) (*protos.VMResponse, error) {
	log.Printf("Received request to stop VM: %v", req.GetVmName())
	// Implement your VM stop logic here
	return &protos.VMResponse{
		Success: true,
		Message: fmt.Sprintf("VM %s stopped successfully", req.GetVmName()),
	}, nil
}

func (s *server) DestroyVM(ctx context.Context, req *protos.VMRequest) (*protos.VMResponse, error) {
	log.Printf("Received request to destroy VM: %v", req.GetVmName())
	// Implement your VM destroy logic here
	return &protos.VMResponse{
		Success: true,
		Message: fmt.Sprintf("VM %s destroyed successfully", req.GetVmName()),
	}, nil
}

func main() {
	err := os.MkdirAll(vmStatePath, 0755)
	if err != nil {
		log.WithError(err).Fatal("failed to create vm state dir")
	}

	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	s := grpc.NewServer()

	protos.RegisterVMManagementServiceServer(s, &server{})
	log.Printf("Server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
