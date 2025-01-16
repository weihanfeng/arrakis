package fountain

import (
	"fmt"
	"os/exec"

	log "github.com/sirupsen/logrus"
)

type Fountain struct {
	bridgeDevice string
}

func NewFountain(bridgeDevice string) *Fountain {
	return &Fountain{bridgeDevice: bridgeDevice}
}

func (f *Fountain) CreateTapDevice(deviceName string) error {
	if err := exec.Command("ip", "tuntap", "add", "dev", deviceName, "mode", "tap").Run(); err != nil {
		return fmt.Errorf("failed to create: %v: %w", deviceName, err)
	}

	if err := exec.Command("ip", "l", "set", "dev", deviceName, "master", f.bridgeDevice).Run(); err != nil {
		return fmt.Errorf("failed to add: %v to: %v: %w", deviceName, f.bridgeDevice, err)
	}

	if err := exec.Command("ip", "l", "set", deviceName, "up").Run(); err != nil {
		return fmt.Errorf("failed to up: %v: %w", deviceName, err)
	}
	return nil
}

func (f *Fountain) DestroyTapDevice(deviceName string) error {
	log.WithFields(log.Fields{
		"deviceName": deviceName,
	}).Info("destroy tap device")

	// Remove the tap device from the bridge
	if err := exec.Command("ip", "link", "set", deviceName, "nomaster").Run(); err != nil {
		return fmt.Errorf("failed to remove %v from bridge: %w", deviceName, err)
	}

	// Bring the tap device down
	if err := exec.Command("ip", "link", "set", deviceName, "down").Run(); err != nil {
		return fmt.Errorf("failed to bring down %v: %w", deviceName, err)
	}

	// Delete the tap device
	if err := exec.Command("ip", "tuntap", "del", "dev", deviceName, "mode", "tap").Run(); err != nil {
		return fmt.Errorf("failed to delete %v: %w", deviceName, err)
	}
	return nil
}
