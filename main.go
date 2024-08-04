package main

import (
	"context"
	"fmt"

	"github.com/abshkbh/chv-lambda/openapi"
)

func createVM(client *openapi.APIClient) error {
	// Create a new VM configuration
	vmConfig := openapi.VmConfig{
		// Set the VM configuration parameters here
		// For example:
		// Cpus: openapi.CpusConfig{Number: 2},
		// Memory: openapi.MemoryConfig{Size: 1024 * 1024 * 1024}, // 1 GB
		// Kernel: openapi.KernelConfig{Path: "/path/to/kernel"},
		// Disks: []openapi.DiskConfig{
		//     {Path: "/path/to/disk.img"},
		// },
	}

	// Create the request
	req := client.DefaultAPI.CreateVM(context.Background())
	req = req.VmConfig(vmConfig)

	// Execute the request
	resp, err := req.Execute()
	if err != nil {
		return err
	}

	// Check the response
	if resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}

func main() {
	fmt.Println("Hello, World!")
}
