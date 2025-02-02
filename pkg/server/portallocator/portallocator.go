package portallocator

import (
	"fmt"
	"sync"
)

// PortAllocator manages allocation of ports within a specified range
type PortAllocator struct {
	lowPort   int32
	highPort  int32
	available []int32
	mutex     sync.Mutex
}

// NewPortAllocator creates a new port allocator for the given port range
func NewPortAllocator(lowPort, highPort int32) (*PortAllocator, error) {
	if lowPort < 1 || highPort > 65535 || lowPort > highPort {
		return nil, fmt.Errorf("invalid port range: %d-%d", lowPort, highPort)
	}

	allocator := &PortAllocator{
		lowPort:   lowPort,
		highPort:  highPort,
		available: make([]int32, 0, highPort-lowPort+1),
	}

	// Initialize available ports
	for port := lowPort; port <= highPort; port++ {
		allocator.available = append(allocator.available, port)
	}

	return allocator, nil
}

// AllocatePort allocates and returns the next available port
func (a *PortAllocator) AllocatePort() (int32, error) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	if len(a.available) == 0 {
		return 0, fmt.Errorf("no available ports in range %d-%d", a.lowPort, a.highPort)
	}

	// Take the first available port
	port := a.available[0]
	a.available = a.available[1:]

	return port, nil
}

// FreePort returns a port to the pool of available ports
func (a *PortAllocator) FreePort(port int32) error {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	if port < a.lowPort || port > a.highPort {
		return fmt.Errorf("port %d is outside allocator range %d-%d", port, a.lowPort, a.highPort)
	}

	// Check if port is already in available pool
	for _, p := range a.available {
		if p == port {
			return fmt.Errorf("port %d is already free", port)
		}
	}

	a.available = append(a.available, port)
	return nil
}
