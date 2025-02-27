package fountain

import (
	"fmt"
	"os/exec"
	"sync"

	log "github.com/sirupsen/logrus"
	"gvisor.dev/gvisor/pkg/cleanup"
)

const (
	LowID  int32 = 0
	HighID int32 = 65535
)

// TapDevice represents a tap network device
type TapDevice struct {
	Name string
	ID   int32
}

// String implements the fmt.Stringer interface.
func (t *TapDevice) String() string {
	return fmt.Sprintf("TapDevice{Name: %s, ID: %d}", t.Name, t.ID)
}

type Fountain struct {
	bridgeDevice string
	mutex        sync.Mutex
	available    []int32 // Available tap IDs
	lowID        int32   // Lowest ID to allocate
	highID       int32   // Highest ID to allocate
}

func NewFountain(bridgeDevice string) *Fountain {
	f := &Fountain{
		bridgeDevice: bridgeDevice,
		lowID:        LowID,
		highID:       HighID,
		available:    make([]int32, 0, HighID-LowID+1),
	}

	for id := LowID; id <= HighID; id++ {
		f.available = append(f.available, id)
	}
	return f
}

// allocateTapID allocates a new tap device ID (internal use).
func (f *Fountain) allocateTapID() (int32, error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	if len(f.available) == 0 {
		return -1, fmt.Errorf("no available tap device IDs in range %d-%d", f.lowID, f.highID)
	}

	id := f.available[0]
	f.available = f.available[1:]
	return id, nil
}

// freeTapID returns a tap ID to the pool of available IDs (internal use).
func (f *Fountain) freeTapID(id int32) error {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	if id < f.lowID || id > f.highID {
		return fmt.Errorf("tap ID %d is outside allocator range %d-%d", id, f.lowID, f.highID)
	}

	for _, i := range f.available {
		if i == id {
			return fmt.Errorf("tap ID %d is already free", id)
		}
	}
	f.available = append(f.available, id)
	return nil
}

// CreateTapDevice creates a new tap device with an auto-allocated ID and returns a TapDevice
func (f *Fountain) CreateTapDevice() (*TapDevice, error) {
	id, err := f.allocateTapID()
	if err != nil {
		return nil, fmt.Errorf("failed to allocate tap ID: %w", err)
	}

	// Set up cleanup that will free the tap ID if the function returns with an error
	cleanup := cleanup.Make(func() {
		log.WithField("tapID", id).Debug("createTapDevice cleanup")
	})
	defer cleanup.Clean() // This will run the cleanup unless we call cleanup.Release()
	cleanup.Add(func() {
		if err := f.freeTapID(id); err != nil {
			log.WithError(err).Errorf("failed to free tap ID %d during cleanup", id)
		}
	})

	deviceName := fmt.Sprintf("tap%d", id)
	if output, err := exec.Command(
		"ip", "tuntap", "add", "dev", deviceName, "mode", "tap",
	).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to create: %v: %s %w", deviceName, output, err)
	}

	if output, err := exec.Command(
		"ip", "l", "set", "dev", deviceName, "master", f.bridgeDevice,
	).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to add: %v to: %v: %s %w", deviceName, f.bridgeDevice, output, err)
	}

	if output, err := exec.Command(
		"ip", "l", "set", deviceName, "up",
	).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("failed to up: %v: %s %w", deviceName, output, err)
	}

	cleanup.Release()
	return &TapDevice{
		Name: deviceName,
		ID:   id,
	}, nil
}

// DestroyTapDevice destroys a tap device and frees its ID.
func (f *Fountain) DestroyTapDevice(device *TapDevice) error {
	log.WithFields(log.Fields{
		"deviceName": device.Name,
		"deviceID":   device.ID,
	}).Info("destroy tap device")

	// Remove the tap device from the bridge
	if err := exec.Command("ip", "link", "set", device.Name, "nomaster").Run(); err != nil {
		return fmt.Errorf("failed to remove %v from bridge: %w", device.Name, err)
	}

	// Bring the tap device down
	if err := exec.Command("ip", "link", "set", device.Name, "down").Run(); err != nil {
		return fmt.Errorf("failed to bring down %v: %w", device.Name, err)
	}

	// Delete the tap device
	if err := exec.Command("ip", "tuntap", "del", "dev", device.Name, "mode", "tap").Run(); err != nil {
		return fmt.Errorf("failed to delete %v: %w", device.Name, err)
	}

	// Free the ID if it's valid
	if device.ID >= f.lowID && device.ID <= f.highID {
		// Ignore error from freeTapID as the device is already deleted
		_ = f.freeTapID(device.ID)
	}

	return nil
}
