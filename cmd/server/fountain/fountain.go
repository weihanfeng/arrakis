package fountain

import (
	"fmt"
	"os/exec"
)

type Fountain struct {
	bridgeDevice string
}

func NewFountain(bridgeDevice string) *Fountain {
	return &Fountain{bridgeDevice: bridgeDevice}
}

func (f *Fountain) CreateTapDevice(vmName string) (string, error) {
	tapDevice := fmt.Sprintf("tap-%s", vmName)
	if err := exec.Command("ip", "tuntap", "add", "dev", tapDevice, "mode", "tap").Run(); err != nil {
		return "", fmt.Errorf("failed to create: %v: %w", tapDevice, err)
	}

	if err := exec.Command("ip", "l", "set", "dev", tapDevice, "master", f.bridgeDevice).Run(); err != nil {
		return "", fmt.Errorf("failed to add: %v to: %v: %w", tapDevice, f.bridgeDevice, err)
	}

	if err := exec.Command("ip", "l", "set", tapDevice, "up").Run(); err != nil {
		return "", fmt.Errorf("failed to up: %v: %w", tapDevice, err)
	}

	return tapDevice, nil
}

func (f *Fountain) DestroyTapDevice(vmName string) error {
	tapDevice := fmt.Sprintf("tap-%s", vmName)

	// Remove the tap device from the bridge
	if err := exec.Command("ip", "link", "set", tapDevice, "nomaster").Run(); err != nil {
		return fmt.Errorf("failed to remove %v from bridge: %w", tapDevice, err)
	}

	// Bring the tap device down
	if err := exec.Command("ip", "link", "set", tapDevice, "down").Run(); err != nil {
		return fmt.Errorf("failed to bring down %v: %w", tapDevice, err)
	}

	// Delete the tap device
	if err := exec.Command("ip", "tuntap", "del", "dev", tapDevice, "mode", "tap").Run(); err != nil {
		return fmt.Errorf("failed to delete %v: %w", tapDevice, err)
	}

	return nil
}
