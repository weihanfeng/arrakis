package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	log "github.com/sirupsen/logrus"
)

const (
	ifname = "eth0"
	ipBin  = "/usr/bin/ip"
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

// setupNetworking sets up networking inside the guest.
func setupNetworking(guestCIDR string, gatewayIP string) error {
	cmd := exec.Command(ipBin, "l", "set", "lo", "up")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf(
			"failed to set the lo interface up. output: %s, error: %w",
			string(output),
			err,
		)
	}
	log.Info("lo interface up")

	cmd = exec.Command(ipBin, "a", "add", guestCIDR, "dev", ifname)
	output, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf(
			"failed to add IP address to interface. output: %s, error: %w",
			string(output),
			err,
		)
	}

	cmd = exec.Command(ipBin, "l", "set", ifname, "up")
	output, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf(
			"failed to set interface up. output: %s, error: %w",
			string(output),
			err,
		)
	}

	cmd = exec.Command(ipBin, "r", "add", "default", "via", gatewayIP, "dev", ifname)
	output, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf(
			"failed to add default route. output: %s, error: %w",
			string(output),
			err,
		)
	}

	f, err := os.OpenFile("/etc/resolv.conf", os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf(
			"failed to open /etc/resolv.conf. error: %w",
			err,
		)
	}
	defer f.Close()

	_, err = f.WriteString("nameserver 8.8.8.8\n")
	if err != nil {
		return fmt.Errorf(
			"failed to write nameserver to /etc/resolv.conf. error: %w",
			err,
		)
	}
	return nil
}

func setupOverlay() error {
	if err := unix.Mount("/dev/vdb", "/mnt/stateful", "ext4", 0, ""); err != nil {
		return fmt.Errorf("failed to mount ext4: %w", err)
	}

	stateful := "/mnt/stateful"
	if err := unix.Chmod(stateful, 0777); err != nil {
		return fmt.Errorf("failed to chmod /mnt/stateful: %w", err)
	}

	// TODO: Set 777 for now.
	upper := filepath.Join(stateful, "overlay-upper")
	if err := os.MkdirAll(upper, 0777); err != nil {
		return fmt.Errorf("failed to create overlay upper directory: %w", err)
	}

	workdir := filepath.Join(stateful, "overlay-workdir")
	if err := os.MkdirAll(workdir, 0777); err != nil {
		return fmt.Errorf("failed to create overlay workdir directory: %w", err)
	}

	merged := filepath.Join(stateful, "overlay-merged")
	if err := os.MkdirAll(merged, 0777); err != nil {
		return fmt.Errorf("failed to create overlay merged directory: %w", err)
	}

	lower := "/"
	options := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s", lower, upper, workdir)
	if err := unix.Mount("overlay", merged, "overlay", 0, options); err != nil {
		return fmt.Errorf("failed to mount overlay: %w", err)
	}

	// Move special mounts to the merged directory
	specialMounts := []string{"dev", "run", "proc", "sys"}
	for _, mount := range specialMounts {
		source := filepath.Join("/", mount)
		target := filepath.Join(merged, mount)

		// Perform mount move
		if err := unix.Mount(source, target, "", unix.MS_MOVE, ""); err != nil {
			return fmt.Errorf("failed to move mount %s to %s: %w", source, target, err)
		}
		log.Infof("Successfully moved %s to %s", source, target)
	}

	// Create oldroot directory for pivot_root
	oldroot := filepath.Join(merged, "oldroot")
	if err := os.MkdirAll(oldroot, 0777); err != nil {
		return fmt.Errorf("failed to create oldroot directory: %w", err)
	}

	// Change to the new root directory
	if err := os.Chdir(merged); err != nil {
		return fmt.Errorf("failed to change directory to %s: %w", merged, err)
	}

	// Perform pivot_root
	if err := unix.PivotRoot(".", "oldroot"); err != nil {
		return fmt.Errorf("failed to pivot_root: %w", err)
	}
	log.Info("Successfully performed pivot_root")

	oldrootPostPivot := filepath.Join("/oldroot", stateful)
	if err := unix.Unmount(oldrootPostPivot, 0); err != nil {
		return fmt.Errorf("failed to unmount oldroot: %s: %w", oldrootPostPivot, err)
	}
	log.Info("Successfully unmounted oldroot")
	return nil
}

func main() {
	log.Infof("starting guestinit")
	if err := setupOverlay(); err != nil {
		log.WithError(err).Error("failed to setup overlay")
	}

	guestCIDR, gatewayIP, err := parseNetworkingMetadata()
	if err != nil {
		log.WithError(err).Error("failed to parse guest networking metadata")
	}

	if err := setupNetworking(guestCIDR, gatewayIP); err != nil {
		log.WithError(err).Error("failed to setup networking")
	}
	log.Info("guestinit exiting...")
}
