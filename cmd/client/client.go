package main

import (
	"context"
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/urfave/cli/v2"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "github.com/abshkbh/chv-lambda/out/protos"
)

const (
	defaultServerAddress = "localhost:50051"
)

func manageVM(c *cli.Context, action string) error {
	if c.NArg() < 1 {
		return fmt.Errorf("VM name is required")
	}
	vmName := c.String("name")
	serverAddr := c.String("server")

	conn, err := grpc.NewClient(serverAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("failed to connect: %v", err)
	}
	defer conn.Close()

	client := pb.NewVMManagementServiceClient(conn)
	ctx := context.Background()

	request := &pb.VMRequest{VmName: vmName}
	var actionErr error

	switch action {
	case "start":
		_, actionErr = client.StartVM(ctx, request)
	case "stop":
		_, actionErr = client.StopVM(ctx, request)
	case "destroy":
		_, actionErr = client.DestroyVM(ctx, request)
	default:
		return fmt.Errorf("unknown action: %s", action)
	}

	if actionErr != nil {
		return fmt.Errorf("error performing %s action: %v", action, actionErr)
	}

	log.Infof("Successfully %sed VM: %s\n", action, vmName)
	return nil
}

func main() {
	app := &cli.App{
		Name:  "vm-cli",
		Usage: "A CLI for managing VMs",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "server",
				Aliases: []string{"s"},
				Value:   defaultServerAddress,
				Usage:   "gRPC server address",
			},
		},
		Commands: []*cli.Command{
			{
				Name:  "start",
				Usage: "Start a VM",
				Action: func(ctx *cli.Context) error {
					return manageVM(ctx, "start")
				},
			},
			{
				Name:  "stop",
				Usage: "Stop a VM",
				Action: func(c *cli.Context) error {
					return manageVM(c, "stop")
				},
			},
			{
				Name:  "destroy",
				Usage: "Destroy a VM",
				Action: func(c *cli.Context) error {
					return manageVM(c, "destroy")
				},
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
