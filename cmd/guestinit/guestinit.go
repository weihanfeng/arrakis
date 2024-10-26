package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"

	log "github.com/sirupsen/logrus"
)

const (
	ifname = "eth0"
	ipBin  = "/usr/bin/ip"
	// Node is already installed on the rootfs. But we do need to add it to the path.
	paths          = "/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin:/usr/bin/versions/node/v22.9.0/bin"
	bashBin        = "/bin/bash"
	serverIpEnvVar = "SERVER_IP"
)

// parseKeyFromCmdLine parses a key from the kernel command line. Assumes each
// key:val is present like key="val" in /proc/cmdline.
func parseKeyFromCmdLine(prefix string) (string, error) {
	cmdline, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return "", fmt.Errorf("failed to read /proc/cmdline: %w", err)
	}

	key := prefix + "="
	cmdlineStr := string(cmdline)

	start := strings.Index(cmdlineStr, key)
	if start == -1 {
		return "", fmt.Errorf("key %q not found in kernel command line", key)
	}

	start += len(key)
	value := strings.TrimPrefix(cmdlineStr[start:], "\"")
	end := strings.IndexByte(value, '"')
	if end == -1 {
		return "", fmt.Errorf("unclosed quote for key %q in kernel command line", key)
	}
	return value[:end], nil
}

// parseNetworkingMetadata parses the networking metadata from the kernel command line.
func parseNetworkingMetadata() (string, string, error) {
	guestCIDR, err := parseKeyFromCmdLine("guest_ip")
	if err != nil {
		return "", "", fmt.Errorf("failed to parse guest_ip: %w", err)
	}

	gatewayCIDR, err := parseKeyFromCmdLine("gateway_ip")
	if err != nil {
		return "", "", fmt.Errorf("failed to parse gateway_ip: %w", err)
	}

	if guestCIDR == "" || gatewayCIDR == "" {
		return "", "", fmt.Errorf("guest_ip or gateway_ip not found in kernel command line")
	}

	// gateway's IP needs to be returned without the subnet mask.
	gatewayIP, _, err := net.ParseCIDR(gatewayCIDR)
	if err != nil {
		return "", "", fmt.Errorf("failed to parse gatewayCIDR: %w", err)
	}

	return guestCIDR, gatewayIP.String(), nil
}

// startEntryPointInBg starts the entry point in the background.
func startEntryPointInBg(entryPoint string, wg *sync.WaitGroup) error {
	// Parse `entryPoint` by splitting on space.
	parts := strings.Fields(entryPoint)
	if len(parts) == 0 {
		return fmt.Errorf("empty entry point")
	}

	command := parts[0]
	args := parts[1:]

	// Create the command.
	cmd := exec.Command(command, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	go runCommand(cmd, wg)
	log.Infof("Started entry point command: %s", entryPoint)
	return nil
}

func startSshServerInBg(wg *sync.WaitGroup) error {
	// Needed to start sshd.
	err := os.MkdirAll("/run/sshd", 0755)
	if err != nil {
		return fmt.Errorf("error creating /run/sshd: %w", err)
	}

	cmd := exec.Command("/usr/sbin/sshd")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	go runCommand(cmd, wg)
	return nil
}

func mount(source, target, fsType string, flags uintptr, data ...string) error {
	if _, err := os.Stat(target); os.IsNotExist(err) {
		err := os.MkdirAll(target, 0755)
		if err != nil {
			return fmt.Errorf("error creating: %s: %w", target, err)
		}
	}

	d := ""
	if len(data) > 0 {
		d = data[0]
	}

	err := syscall.Mount(source, target, fsType, flags, d)
	if err != nil {
		return fmt.Errorf("error mounting %s to %s, error: %w", source, target, err)
	}
	return nil
}

// setupNetworking sets up networking inside the guest.
func setupNetworking(guestCIDR string, gatewayIP string) error {
	cmd := exec.Command(ipBin, "l", "set", "lo", "up")
	err := cmd.Run()
	if err != nil {
		log.WithError(err).Fatal("failed to set the lo interface up")
	}

	cmd = exec.Command(ipBin, "a", "add", guestCIDR, "dev", ifname)
	err = cmd.Run()
	if err != nil {
		log.WithError(err).Fatal("failed to add IP address to interface")
	}

	cmd = exec.Command(ipBin, "l", "set", ifname, "up")
	err = cmd.Run()
	if err != nil {
		log.WithError(err).Fatal("failed to set interface up")
	}

	cmd = exec.Command(ipBin, "r", "add", "default", "via", gatewayIP, "dev", ifname)
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
	return nil
}

func runCommand(cmd *exec.Cmd, wg *sync.WaitGroup) error {
	defer wg.Done()

	wg.Add(1)
	err := cmd.Start()
	if err != nil {
		return fmt.Errorf("failed to start: %v", cmd)
	}

	err = cmd.Wait()
	if err != nil {
		return fmt.Errorf("error while watiing for cmd: %v err: %w", cmd, err)
	}
	return nil
}

func remountRootAsReadOnly() error {
	cmd := exec.Command("mount", "-o", "remount,ro", "/")
	return cmd.Run()
}

func main() {
	log.Infof("starting guestinit")

	// Setup essential mounts.
	err := mount("none", "/proc", "proc", 0)
	if err != nil {
		log.WithError(err).Fatalf("Error mounting proc")
	}
	err = mount("none", "/dev/pts", "devpts", 0)
	if err != nil {
		log.WithError(err).Fatalf("Error mounting devpts")
	}
	err = mount("none", "/dev/mqueue", "mqueue", 0)
	if err != nil {
		log.WithError(err).Fatalf("Error mounting mqueue")
	}
	err = mount("none", "/dev/shm", "tmpfs", 0)
	if err != nil {
		log.WithError(err).Fatalf("Error mounting shm")
	}
	err = mount("none", "/sys", "sysfs", 0)
	if err != nil {
		log.WithError(err).Fatalf("Error mounting sysfs")
	}
	err = mount("none", "/sys/fs/cgroup", "cgroup", 0)
	if err != nil {
		log.WithError(err).Fatalf("Error mounting cgroup")
	}

	err = os.Setenv("PATH", paths)
	if err != nil {
		log.WithError(err).Fatalf("Error setting PATH")
	}

	guestCIDR, gatewayIP, err := parseNetworkingMetadata()
	if err != nil {
		log.WithError(err).Fatal("failed to parse guest networking metadata")
	}

	guestIP, _, err := net.ParseCIDR(guestCIDR)
	if err != nil {
		log.WithError(err).Fatalf("failed to parse guest CIDR: %v", err)
	}

	// This will be used by custom servers started by the user in this VM.
	err = os.Setenv(serverIpEnvVar, guestIP.String())
	if err != nil {
		log.WithError(err).Fatalf("Error setting SERVER_IP: %s", guestIP.String())
	}

	// Setup networking.
	err = setupNetworking(guestCIDR, gatewayIP)
	if err != nil {
		log.WithError(err).Fatal("failed to setup networking")
	}

	var wg sync.WaitGroup
	// Start the entry point command optionally specified by the user.
	entryPoint, err := parseKeyFromCmdLine("entry_point")
	if err != nil {
		log.Warn("no valid entry point found")
	} else if entryPoint != "" {
		log.Infof("starting entry point command: %s", entryPoint)
		err := startEntryPointInBg(entryPoint, &wg)
		if err != nil {
			log.WithError(err).Fatal("failed to start entry point")
		}
	}

	// Start the ssh server so that the user can log in to the VM for debugging.
	err = startSshServerInBg(&wg)
	if err != nil {
		log.WithError(err).Fatal("failed to start ssh server")
	}

	// Mount as ro so that we can't be corrupted by malicious code.
	err = remountRootAsReadOnly()
	if err != nil {
		log.WithError(err).Fatal("failed to remount root as readonly")
	}

	err = mount("tmpfs", "/tmp", "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV, "size=128M")
	if err != nil {
		log.WithError(err).Fatal("failed to mount tmpfs as writable")
	}

	log.Info("reaping processes")
	wg.Wait()
	log.Info("guestinit successfully exiting")
}
