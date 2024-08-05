package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/abshkbh/chv-lambda/openapi"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

const (
	binPath         = "/home/maverick/projects/chv-lambda/resources/bin"
	numBootVcpus    = 1
	memorySizeBytes = 512 * 1024 * 1024
	// Case sensitive.
	serialPortMode = "Tty"
	// Case sensitive.
	consolePortMode = "Off"
	chvBinPath      = "/home/maverick/projects/chv-lambda/resources/bin/cloud-hypervisor"
)

var (
	kernelPath    = binPath + "/compiled-vmlinux.bin"
	rootfsPath    = binPath + "/ext4.img"
	initPath      = "/bin/bash"
	kernelCmdline = "console=ttyS0 root=/dev/vda rw init=" + initPath
)

// runCloudHypervisor starts the chv binary at `chvBinPath` on the given `apiSocket`.
func runCloudHypervisor(chvBinPath string, apiSocketPath string) error {
	cmd := exec.Command(chvBinPath, "--api-socket", apiSocketPath)

	// Run the command and capture output and error
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("error spawning chv binary: %w output: %s", err, string(out))
	}

	log.Println("Spawn successful")
	return nil
}

func getSocketPath(vmName string) string {
	return fmt.Sprintf("/tmp/%s.sock", vmName)
}

func createVM(ctx context.Context, vmName string) error {
	apiSocketPath := getSocketPath(vmName)

	go func() {
		err := runCloudHypervisor(chvBinPath, apiSocketPath)
		if err != nil {
			log.WithError(err).Fatal("failed to spawn cloud-hypervisor server")
		}
	}()

	apiClient := createApiClient(apiSocketPath)
	err := waitForServer(context.Background(), apiClient, 10*time.Second)
	if err != nil {
		log.WithError(err).Fatal("failed to wait for cloud-hypervisor server")
	}

	// Create a new VM configuration
	vmConfig := openapi.VmConfig{
		Payload: openapi.PayloadConfig{
			Kernel:  &kernelPath,
			Cmdline: &kernelCmdline,
		},
		Disks:   []openapi.DiskConfig{{Path: rootfsPath}},
		Cpus:    &openapi.CpusConfig{BootVcpus: numBootVcpus, MaxVcpus: numBootVcpus},
		Memory:  &openapi.MemoryConfig{Size: memorySizeBytes},
		Serial:  openapi.NewConsoleConfig(serialPortMode),
		Console: openapi.NewConsoleConfig(consolePortMode),
	}

	req := apiClient.DefaultAPI.CreateVM(ctx)
	req = req.VmConfig(vmConfig)

	// Execute the request
	resp, err := req.Execute()
	if err != nil {
		return fmt.Errorf("failed to start VM: %w %v", err, resp.Body)
	}

	log.Infof("create resp: %v", resp)
	if resp.StatusCode != 200 && resp.StatusCode != 204 {
		return fmt.Errorf("failed to start VM. bad status: %v", resp)
	}

	log.Infof("before bootVM")
	resp, err = apiClient.DefaultAPI.BootVM(ctx).Execute()
	if err != nil {
		return fmt.Errorf("failed to boot VM: %w %v", err, resp.Body)
	}

	log.Infof("boot resp: %v", resp)
	if resp.StatusCode != 200 && resp.StatusCode != 204 {
		return fmt.Errorf("failed to boot VM. bad status: %v", resp)
	}

	return nil
}

func info(ctx context.Context) (string, error) {
	apiSocketPath := getSocketPath("dummy")

	go func() {
		err := runCloudHypervisor(chvBinPath, apiSocketPath)
		if err != nil {
			log.WithError(err).Fatal("failed to spawn cloud-hypervisor server")
		}
	}()

	apiClient := createApiClient(apiSocketPath)
	err := waitForServer(context.Background(), apiClient, 10*time.Second)
	if err != nil {
		log.WithError(err).Fatal("failed to wait for cloud-hypervisor server")
	}

	resp, r, err := apiClient.DefaultAPI.VmmPingGet(ctx).Execute()
	if err != nil {
		return "", fmt.Errorf("sanity check failed: %w", err)
	}

	if r.StatusCode != 200 {
		return "", fmt.Errorf("sanity check failed. status code: %d", r.StatusCode)
	}

	return fmt.Sprintf("chv buildVersion=%s", *resp.BuildVersion), nil
}

func unixSocketClient(socketPath string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		},
		Timeout: time.Second * 30,
	}
}

func createApiClient(apiSocketPath string) *openapi.APIClient {
	configuration := openapi.NewConfiguration()
	configuration.HTTPClient = unixSocketClient(apiSocketPath)
	configuration.Servers = openapi.ServerConfigurations{
		{
			URL: "http://localhost/api/v1",
		},
	}
	return openapi.NewAPIClient(configuration)
}

func waitForServer(ctx context.Context, apiClient *openapi.APIClient, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		for {
			select {
			case <-ctx.Done():
				errCh <- ctx.Err()
				return
			default:
				resp, r, err := apiClient.DefaultAPI.VmmPingGet(ctx).Execute()
				if err == nil {
					log.WithFields(log.Fields{
						"buildVersion": *resp.BuildVersion,
						"statusCode":   r.StatusCode,
					}).Info("cloud-hypervisor server up")
					errCh <- nil
					return
				}
				time.Sleep(10 * time.Millisecond)
			}
		}
	}()

	return <-errCh
}

func main() {
	app := &cli.App{
		Name:  "chv-cli",
		Usage: "A CLI for managing Cloud Hypervisor VMs",
		Commands: []*cli.Command{
			{
				Name:    "create",
				Aliases: []string{"c"},
				Usage:   "Create and start a new VM",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "name",
						Aliases:  []string{"n"},
						Usage:    "Name of the VM to create",
						Required: true,
					},
				},
				Action: func(cCtx *cli.Context) error {
					vmName := cCtx.String("name")
					// TODO: Use correct ctx.
					return createVM(context.Background(), vmName)
				},
			},
			{
				Name:    "info",
				Aliases: []string{"i"},
				Usage:   "Checks if chv server is running",
				Action: func(cCtx *cli.Context) error {
					// TODO: Use cCtx here.
					buildVersion, err := info(context.Background())
					if err != nil {
						return err
					}
					log.WithField("buildVersion", buildVersion).Info("chv server healthy")
					return nil
				},
			},
			{
				Name:    "help",
				Aliases: []string{"h"},
				Usage:   "Show help information for commands",
				Action: func(cCtx *cli.Context) error {
					return cli.ShowAppHelp(cCtx)
				},
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.WithError(err).Fatal("exit")
	}
}
