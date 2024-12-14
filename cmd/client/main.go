package main

import (
	"context"
	"fmt"
	"net"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/urfave/cli/v2"

	"github.com/abshkbh/chv-lambda/out/gen/serverapi"
	"github.com/abshkbh/chv-lambda/pkg/config"
)

const (
	defaultServerAddress = config.RestServerAddr + ":" + config.RestServerPort
)

var (
	apiClient *serverapi.APIClient
)

func stopVM(vmName string) error {
	vmRequest := &serverapi.VMRequest{
		VmName: serverapi.PtrString(vmName),
	}

	_, _, err := apiClient.DefaultAPI.VmStopPost(context.Background()).VMRequest(*vmRequest).Execute()
	if err != nil {
		return fmt.Errorf("failed to stop VM: %w", err)
	}

	log.Infof("successfully stopped VM: %s", vmName)
	return nil
}

func destroyVM(vmName string) error {
	vmRequest := &serverapi.VMRequest{
		VmName: serverapi.PtrString(vmName),
	}

	_, _, err := apiClient.DefaultAPI.VmDestroyPost(context.Background()).VMRequest(*vmRequest).Execute()
	if err != nil {
		return fmt.Errorf("failed to destroy VM: %w", err)
	}

	log.Infof("successfully destroyed VM: %s", vmName)
	return nil
}

func destroyAllVMs() error {
	_, _, err := apiClient.DefaultAPI.VmDestroyAllPost(context.Background()).Execute()
	if err != nil {
		return fmt.Errorf("failed to destroy all VMs: %w", err)
	}

	log.Infof("destroyed all VMs")
	return nil
}

func startVM(vmName string, entryPoint string) error {
	startVMRequest := &serverapi.StartVMRequest{
		VmName:     serverapi.PtrString(vmName),
		EntryPoint: serverapi.PtrString(entryPoint),
	}

	resp, _, err := apiClient.DefaultAPI.VmStartPost(context.Background()).StartVMRequest(*startVMRequest).Execute()
	if err != nil {
		return fmt.Errorf("failed to start VM: %w", err)
	}

	resp_bytes, err := resp.MarshalJSON()
	if err != nil {
		return fmt.Errorf("failed to marshal response: %w", err)
	}
	log.Infof("started VM: %v", string(resp_bytes))
	return nil
}

func listAllVMs() error {
	resp, _, err := apiClient.DefaultAPI.VmListGet(context.Background()).Execute()
	if err != nil {
		return fmt.Errorf("failed to list VM: %w", err)
	}

	resp_bytes, err := resp.MarshalJSON()
	if err != nil {
		return fmt.Errorf("failed to marshal response: %w", err)
	}
	log.Infof("VMs: %v", string(resp_bytes))
	return nil
}

func createApiClient(serverAddr string) (*serverapi.APIClient, error) {
	host, port, err := net.SplitHostPort(serverAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse server address: %v", err)
	}

	serverConfiguration := &serverapi.ServerConfiguration{
		URL:         "http://{host}:{port}",
		Description: "Development server",
		Variables: map[string]serverapi.ServerVariable{
			"host": {
				Description:  "host",
				DefaultValue: host,
			},
			"port": {
				Description:  "port",
				DefaultValue: port,
			},
		},
	}

	configuration := serverapi.NewConfiguration()
	configuration.Servers = serverapi.ServerConfigurations{
		*serverConfiguration,
	}
	apiClient = serverapi.NewAPIClient(configuration)

	return apiClient, nil
}

func listVM(vmName string) error {
	resp, _, err := apiClient.DefaultAPI.VmNameGet(context.Background(), vmName).Execute()
	if err != nil {
		return fmt.Errorf("failed to list VM: %w", err)
	}

	resp_bytes, err := resp.MarshalJSON()
	if err != nil {
		return fmt.Errorf("failed to marshal response: %w", err)
	}
	log.Infof("VM: %v", string(resp_bytes))
	return nil
}

func main() {
	var err error
	apiClient, err = createApiClient(defaultServerAddress)
	if err != nil {
		log.Fatalf("failed to initialize api client: %v", err)
	}

	app := &cli.App{
		Name:  "vm-cli",
		Usage: "A CLI for managing VMs",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "server",
				Aliases: []string{"s"},
				Value:   defaultServerAddress,
				Usage:   "gRPC server address",
				Action: func(ctx *cli.Context, value string) error {
					apiClient, err = createApiClient(value)
					if err != nil {
						return fmt.Errorf("failed to initialize api client: %v", err)
					}
					return nil
				},
			},
		},
		Commands: []*cli.Command{
			{
				Name:  "start",
				Usage: "Start a VM",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "name",
						Aliases:  []string{"n"},
						Usage:    "Name of the VM to create",
						Required: true,
					},
					&cli.StringFlag{
						Name:     "entry-point",
						Aliases:  []string{"e"},
						Usage:    "Entry point of the VM",
						Required: false,
					},
				},
				Action: func(ctx *cli.Context) error {
					return startVM(ctx.String("name"), ctx.String("entry-point"))
				},
			},
			{
				Name:  "stop",
				Usage: "Stop a VM",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "name",
						Aliases:  []string{"n"},
						Usage:    "Name of the VM to stop",
						Required: true,
					},
				},
				Action: func(ctx *cli.Context) error {
					return stopVM(ctx.String("name"))
				},
			},
			{
				Name:  "destroy",
				Usage: "Destroy a VM",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "name",
						Aliases:  []string{"n"},
						Usage:    "Name of the VM to destroy",
						Required: true,
					},
				},
				Action: func(ctx *cli.Context) error {
					return destroyVM(ctx.String("name"))
				},
			},
			{
				Name:  "destroy-all",
				Usage: "Destroy all VMs",
				Action: func(ctx *cli.Context) error {
					return destroyAllVMs()
				},
			},
			{
				Name:  "list-all",
				Usage: "List all VMs",
				Action: func(ctx *cli.Context) error {
					return listAllVMs()
				},
			},
			{
				Name:  "list",
				Usage: "List VM info",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "name",
						Aliases:  []string{"n"},
						Usage:    "Name of the VM to destroy",
						Required: true,
					},
				},
				Action: func(ctx *cli.Context) error {
					return listVM(ctx.String("name"))
				},
			},
		},
	}

	err = app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
