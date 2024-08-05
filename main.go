package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/abshkbh/chv-lambda/openapi"
)

const (
	binPath         = "/home/maverick/projects/chv-lambda/resources/bin"
	numBootVcpus    = 1
	memorySizeBytes = 512 * 1024 * 1024
	serialPortMode  = "tty"
	consolePortMode = "off"
	chvBinPath      = "/home/maverick/projects/chv-lambda/resources/bin/cloud-hypervisor"
	apiSocketPath   = "/tmp/chv.sock"
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
	_, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("error spawning chv binary: %w", err)
	}

	log.Println("Spawn successful")
	return nil
}

func createVM(ctx context.Context, client *openapi.APIClient) error {
	// Create a new VM configuration
	vmConfig := openapi.VmConfig{
		Payload: openapi.PayloadConfig{
			Kernel:  &kernelPath,
			Cmdline: &kernelCmdline,
		},
		Disks:   []openapi.DiskConfig{{Path: rootfsPath}},
		Cpus:    &openapi.CpusConfig{BootVcpus: numBootVcpus},
		Memory:  &openapi.MemoryConfig{Size: memorySizeBytes},
		Serial:  openapi.NewConsoleConfig(serialPortMode),
		Console: openapi.NewConsoleConfig(consolePortMode),
	}

	// Create the request
	req := client.DefaultAPI.CreateVM(ctx)
	req = req.VmConfig(vmConfig)

	// Execute the request
	resp, err := req.Execute()
	if err != nil {
		return fmt.Errorf("failed to start VM: %w", err)
	}

	// Check the response
	if resp.StatusCode != 200 {
		return fmt.Errorf("failed to start VM: %d", resp.StatusCode)
	}

	return nil
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

func main() {
	fmt.Println("Hello, World!")

	go func() {
		err := runCloudHypervisor(chvBinPath, apiSocketPath)
		if err != nil {
			log.Fatalf("failed to spawn chv: %v", err)
		}
	}()
	log.Println("After spawn")
	time.Sleep(5 * time.Second)

	configuration := openapi.NewConfiguration()
	configuration.HTTPClient = unixSocketClient(apiSocketPath)
	configuration.Servers = openapi.ServerConfigurations{
		{
			URL: "http://localhost", // This is required but won't be used
		},
	}
	apiClient := openapi.NewAPIClient(configuration)

	// Now use the apiClient to make requests
	ctx := context.Background()
	resp, r, err := apiClient.DefaultAPI.VmmPingGet(ctx).Execute()
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		fmt.Printf("Full HTTP response: %v\n", r)
	}
	// Process the response
	fmt.Printf("Response from server: %v\n", resp)

	err = os.Remove(apiSocketPath)
	if err != nil {
		log.Printf("failed to delete api socket: %v", err)
	}
}
