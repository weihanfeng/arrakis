package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"

	"github.com/abshkbh/chv-starter-pack/out/gen/serverapi"
	"github.com/abshkbh/chv-starter-pack/pkg/config"
)

var (
	apiClient *serverapi.APIClient
)

func stopVM(vmName string) error {
	req := apiClient.DefaultAPI.VmsNamePatch(context.Background(), vmName)

	req = req.VmsNamePatchRequest(serverapi.VmsNamePatchRequest{
		Status: serverapi.PtrString("stopped"),
	})

	_, httpResp, err := req.Execute()
	if err != nil {
		body, _ := io.ReadAll(httpResp.Body)
		return fmt.Errorf("failed to stop VM: error: %s code: %v", string(body), err)
	}

	log.Infof("successfully stopped VM: %s", vmName)
	return nil
}

func destroyVM(vmName string) error {
	_, http_resp, err := apiClient.
		DefaultAPI.
		VmsNameDelete(context.Background(), vmName).Execute()
	if err != nil {
		body, _ := io.ReadAll(http_resp.Body)
		return fmt.Errorf("failed to destroy VM: error: %s code: %v", string(body), err)
	}

	log.Infof("successfully destroyed VM: %s", vmName)
	return nil
}

func destroyAllVMs() error {
	_, http_resp, err := apiClient.DefaultAPI.VmsDelete(context.Background()).Execute()
	if err != nil {
		body, _ := io.ReadAll(http_resp.Body)
		return fmt.Errorf("failed to destroy all VMs: error: %s code: %v", string(body), err)
	}

	log.Infof("destroyed all VMs")
	return nil
}

func startVM(
	vmName string,
	kernel string,
	rootfs string,
	entryPoint string,
	snapshotPath string,
) error {
	var startVMRequest *serverapi.StartVMRequest
	if snapshotPath != "" {
		// If snapshot path is provided, restore the VM from the snapshot,
		startVMRequest = &serverapi.StartVMRequest{
			VmName:     serverapi.PtrString(vmName),
			EntryPoint: serverapi.PtrString(snapshotPath),
		}
	} else {
		startVMRequest = &serverapi.StartVMRequest{
			VmName:     serverapi.PtrString(vmName),
			Kernel:     serverapi.PtrString(kernel),
			Rootfs:     serverapi.PtrString(rootfs),
			EntryPoint: serverapi.PtrString(entryPoint),
		}
	}

	resp, http_resp, err := apiClient.DefaultAPI.
		VmsPost(context.Background()).
		StartVMRequest(*startVMRequest).Execute()
	if err != nil {
		body, _ := io.ReadAll(http_resp.Body)
		return fmt.Errorf("failed to start VM: error: %s code: %v", string(body), err)
	}

	resp_bytes, err := resp.MarshalJSON()
	if err != nil {
		return fmt.Errorf("failed to marshal response: %w", err)
	}
	log.Infof("started VM: %v", string(resp_bytes))
	return nil
}

func listAllVMs() error {
	resp, http_resp, err := apiClient.DefaultAPI.VmsGet(context.Background()).Execute()
	if err != nil {
		body, _ := io.ReadAll(http_resp.Body)
		return fmt.Errorf("failed to list all VMs: error: %s code: %v", string(body), err)
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
	resp, _, err := apiClient.DefaultAPI.VmsNameGet(context.Background(), vmName).Execute()
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

func snapshotVM(vmName string, outputDir string) error {
	if outputDir == "" {
		timestamp := time.Now().Format("20060102-150405")
		outputDir = fmt.Sprintf("snapshot-%s-%s", vmName, timestamp)
	}

	// Convert the path to absolute path
	absPath, err := filepath.Abs(outputDir)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %w", err)
	}

	req := apiClient.DefaultAPI.VmsNameSnapshotsPost(context.Background(), vmName)
	req = req.VmsNameSnapshotsPostRequest(serverapi.VmsNameSnapshotsPostRequest{
		OutputFile: serverapi.PtrString(absPath),
	})

	_, httpResp, err := req.Execute()
	if err != nil {
		body, _ := io.ReadAll(httpResp.Body)
		return fmt.Errorf("failed to create snapshot: error: %s code: %v", string(body), err)
	}

	log.Infof("successfully created snapshot for VM %s in directory %s", vmName, outputDir)
	return nil
}

func restoreVM(vmName string, snapshotPath string) error {
	snapshotAbsPath, err := filepath.Abs(snapshotPath)
	if err != nil {
		return fmt.Errorf("failed to get absolute path for snapshot: %w", err)
	}
	return startVM(vmName, "", "", "", snapshotAbsPath)
}

func pauseVM(vmName string) error {
	req := apiClient.DefaultAPI.VmsNamePatch(context.Background(), vmName)

	req = req.VmsNamePatchRequest(serverapi.VmsNamePatchRequest{
		Status: serverapi.PtrString("paused"),
	})

	_, httpResp, err := req.Execute()
	if err != nil {
		body, _ := io.ReadAll(httpResp.Body)
		return fmt.Errorf("failed to pause VM: error: %s code: %v", string(body), err)
	}

	log.Infof("successfully paused VM: %s", vmName)
	return nil
}

func main() {
	app := &cli.App{
		Name:  "chv-client",
		Usage: "A CLI for managing VMs",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "config",
				Aliases: []string{"c"},
				Usage:   "Path to config file",
				Value:   "./config.yaml",
			},
		},
		Before: func(ctx *cli.Context) error {
			configPath := ctx.String("config")
			clientConfig, err := config.GetClientConfig(configPath)
			if err != nil {
				return fmt.Errorf("failed to get client config: %v", err)
			}
			log.Infof("client config: %v", clientConfig)

			apiClient, err = createApiClient(
				fmt.Sprintf("%s:%s", clientConfig.ServerHost, clientConfig.ServerPort),
			)
			if err != nil {
				return fmt.Errorf("failed to initialize api client: %v", err)
			}
			return nil
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
						Name:    "kernel",
						Aliases: []string{"k"},
						Usage:   "Path of the kernel image to be used",
					},
					&cli.StringFlag{
						Name:    "rootfs",
						Aliases: []string{"r"},
						Usage:   "Path of the rootfs image to be used",
					},
					&cli.StringFlag{
						Name:     "entry-point",
						Aliases:  []string{"e"},
						Usage:    "Entry point of the VM",
						Required: false,
					},
					&cli.StringFlag{
						Name:    "snapshot",
						Aliases: []string{"s"},
						Usage:   "Path to snapshot directory to restore from",
					},
				},
				Action: func(ctx *cli.Context) error {
					return startVM(
						ctx.String("name"),
						ctx.String("kernel"),
						ctx.String("rootfs"),
						ctx.String("entry-point"),
						ctx.String("snapshot"),
					)
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
			{
				Name:  "snapshot",
				Usage: "Create a snapshot of a VM",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "name",
						Aliases:  []string{"n"},
						Usage:    "Name of the VM",
						Required: true,
					},
					&cli.StringFlag{
						Name:     "output",
						Aliases:  []string{"o"},
						Usage:    "Output directory path for the snapshot",
						Required: false,
					},
				},
				Action: func(ctx *cli.Context) error {
					return snapshotVM(ctx.String("name"), ctx.String("output"))
				},
			},
			{
				Name:  "restore",
				Usage: "Restore a VM from a snapshot",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "name",
						Aliases:  []string{"n"},
						Usage:    "Name to give to the restored VM",
						Required: true,
					},
					&cli.StringFlag{
						Name:     "snapshot",
						Aliases:  []string{"s"},
						Usage:    "Path to the snapshot directory",
						Required: true,
					},
				},
				Action: func(ctx *cli.Context) error {
					return restoreVM(ctx.String("name"), ctx.String("snapshot"))
				},
			},
			{
				Name:  "pause",
				Usage: "Pause a running VM",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "name",
						Aliases:  []string{"n"},
						Usage:    "Name of the VM to pause",
						Required: true,
					},
				},
				Action: func(ctx *cli.Context) error {
					return pauseVM(ctx.String("name"))
				},
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
