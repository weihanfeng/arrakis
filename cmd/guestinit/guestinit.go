package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"

	log "github.com/sirupsen/logrus"
)

const (
	guestIP   = "10.20.1.2/24"
	gatewayIP = "10.20.1.1"
	ifname    = "eth0"
)

func mount(source, target, fsType string, flags uintptr) error {
	if _, err := os.Stat(target); os.IsNotExist(err) {
		err := os.MkdirAll(target, 0755)
		if err != nil {
			return fmt.Errorf("error creating: %s: %w", target, err)
		}
	}

	err := syscall.Mount(source, target, fsType, flags, "")
	if err != nil {
		return fmt.Errorf("error mounting %s to %s, error: %w", source, target, err)
	}

	return nil
}

func main() {
	log.Infof("guestinit PATH: %s", os.Getenv("PATH"))

	// Setup essential mounts.
	mount("none", "/proc", "proc", 0)
	mount("none", "/dev/pts", "devpts", 0)
	mount("none", "/dev/mqueue", "mqueue", 0)
	mount("none", "/dev/shm", "tmpfs", 0)
	mount("none", "/sys", "sysfs", 0)
	mount("none", "/sys/fs/cgroup", "cgroup", 0)

	// Setup networking.
	cmd := exec.Command("ip", "a", "add", guestIP, "dev", ifname)
	err := cmd.Run()
	if err != nil {
		log.WithError(err).Fatal("failed to add IP address to interface")
	}

	cmd = exec.Command("ip", "l", "set", ifname, "up")
	err = cmd.Run()
	if err != nil {
		log.WithError(err).Fatal("failed to set interface up")
	}

	cmd = exec.Command("ip", "r", "add", "default", "via", gatewayIP, "dev", ifname)
	err = cmd.Run()
	if err != nil {
		log.WithError(err).Fatal("failed to add default route")
	}

	f, err := os.OpenFile("/etc/resolv.conf", os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		log.WithError(err).Fatal("failed to open /etc/resolv.conf")
	}
	defer f.Close()

	_, err = f.WriteString("nameserver 8.8.8.8\n")
	if err != nil {
		log.WithError(err).Fatal("failed to write nameserver to /etc/resolv.conf")
	}
}
