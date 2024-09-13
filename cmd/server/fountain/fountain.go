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
