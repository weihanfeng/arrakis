package fountain

import (
	"fmt"
	"os/exec"
)

type Fountain struct {
	bridgeDevice string
	nextId       int32
}

func NewFountain(bridgeDevice string) *Fountain {
	return &Fountain{bridgeDevice: bridgeDevice}
}

func (f *Fountain) CreateTapDevice() (retTapDevice string, retErr error) {
	defer func() {
		// TODO: Undo the ip commands if we fail any of the tap operations.
		if retErr != nil {
			f.nextId += 1
		}
	}()

	tapDevice := fmt.Sprintf("tap%d", f.nextId)
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
