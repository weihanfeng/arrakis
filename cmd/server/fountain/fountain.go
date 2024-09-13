package fountain

import (
	"fmt"
	"os/exec"
)

type Fountain struct {
	subnet string
	nextId int32
}

func NewFountain(subnet string) *Fountain {
	return &Fountain{subnet: subnet}
}

func (f *Fountain) CreateTapDevice(bridgeDeviceName string) (retTapDeviceName string, retErr error) {
	defer func() {
		// TODO: Undo the ip commands if we fail any of the tap operations.
		if retErr != nil {
			f.nextId += 1
		}
	}()

	tapDeviceName := fmt.Sprintf("tap%d", f.nextId)
	if err := exec.Command("ip", "tuntap", "add", "dev", tapDeviceName, "mode", "tap").Run(); err != nil {
		return "", fmt.Errorf("failed to create: %v: %w", tapDeviceName, err)
	}

	if err := exec.Command("ip", "l", "set", "dev", tapDeviceName, "master", bridgeDeviceName).Run(); err != nil {
		return "", fmt.Errorf("failed to add: %v to: %v: %w", tapDeviceName, bridgeDeviceName, err)
	}

	if err := exec.Command("ip", "l", "set", tapDeviceName, "up").Run(); err != nil {
		return "", fmt.Errorf("failed to up: %v: %w", tapDeviceName, err)
	}

	return tapDeviceName, nil
}
