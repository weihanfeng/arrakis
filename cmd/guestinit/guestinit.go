package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"

	log "github.com/sirupsen/logrus"
)

const (
	ifname  = "eth0"
	ipBin   = "/usr/bin/ip"
	paths   = "PATH=/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin"
	bashBin = "/bin/bash"
)

// parseNetworkingMetadata parses the networking metadata from the kernel command line.
func parseNetworkingMetadata() (string, string, error) {
	cmdline, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return "", "", fmt.Errorf("failed to read /proc/cmdline: %w", err)
	}

	params := strings.Fields(string(cmdline))
	var guestCIDR, gatewayCIDR string

	for _, param := range params {
		if strings.HasPrefix(param, "guest_ip=") {
			guestCIDR = strings.TrimPrefix(param, "guest_ip=")
		} else if strings.HasPrefix(param, "gateway_ip=") {
			gatewayCIDR = strings.TrimPrefix(param, "gateway_ip=")
		}
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

// parseLangTypeMetadata parses the language type metadata from the kernel command line.
func parseLangTypeMetadata() (string, error) {
	cmdline, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return "", fmt.Errorf("failed to read /proc/cmdline: %w", err)
	}

	params := strings.Fields(string(cmdline))
	prefix_to_find := "lang_type="
	for _, param := range params {
		if strings.HasPrefix(param, prefix_to_find) {
			return strings.TrimPrefix(param, prefix_to_find), nil
		}
	}

	return "", fmt.Errorf("failed to parse lang_type: %w", err)
}

func startLangServerInBg(langType string) (*exec.Cmd, error) {
	if langType != "node" {
		return nil, fmt.Errorf("only node is supported got lang type: %s", langType)
	}

	cmd := exec.Command("/usr/bin/versions/node/v22.9.0/bin/node", "/opt/custom_scripts/server.js")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err := cmd.Start()
	if err != nil {
		return nil, fmt.Errorf("failed to start lang server: %w", err)
	}
	return cmd, nil
}

func startSshServerInBg() (*exec.Cmd, error) {
	// Needed to start sshd.
	err := os.MkdirAll("/run/sshd", 0755)
	if err != nil {
		return nil, fmt.Errorf("error creating /run/sshd: %w", err)
	}

	cmd := exec.Command("/usr/sbin/sshd")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Start()
	if err != nil {
		return nil, fmt.Errorf("failed to start sshd: %w", err)
	}
	return cmd, nil
}

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
	log.Infof("starting guestinit")

	// Setup essential mounts.
	mount("none", "/proc", "proc", 0)
	mount("none", "/dev/pts", "devpts", 0)
	mount("none", "/dev/mqueue", "mqueue", 0)
	mount("none", "/dev/shm", "tmpfs", 0)
	mount("none", "/sys", "sysfs", 0)
	mount("none", "/sys/fs/cgroup", "cgroup", 0)

	guestCIDR, gatewayIP, err := parseNetworkingMetadata()
	if err != nil {
		log.WithError(err).Fatal("failed to parse guest networking metadata")
	}

	// Setup networking.
	cmd := exec.Command(ipBin, "l", "set", "lo", "up")
	err = cmd.Run()
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

	lang_type, err := parseLangTypeMetadata()
	if err != nil {
		log.WithError(err).Fatal("failed to parse lang_type")
	}

	var auxProcesses []*exec.Cmd
	if lang_type != "" {
		log.Infof("starting lang server with lang type: %s", lang_type)
		cmd, err := startLangServerInBg(lang_type)
		if err != nil {
			log.WithError(err).Fatal("failed to start lang server")
		}
		auxProcesses = append(auxProcesses, cmd)
	}

	cmd, err = startSshServerInBg()
	if err != nil {
		log.WithError(err).Fatal("failed to start ssh server")
	}
	log.Infof("started sshd with PID: %d", cmd.Process.Pid)

	log.Infof("starting %s", bashBin)

	cmd = exec.Command(bashBin)
	cmd.Env = append(cmd.Env, paths)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Start()
	if err != nil {
		log.WithError(err).Fatalf("failed to start: %s", bashBin)
	}

	err = cmd.Wait()
	if err != nil {
		log.WithError(err).Fatalf("failed to wait for: %s", bashBin)
	}

	// After the ssh server is done. Reap all the other processes we spawned.
	var waitErr error
	for _, process := range auxProcesses {
		waitErr = errors.Join(process.Wait(), waitErr)
	}
	if waitErr != nil {
		log.WithError(err).Fatal("failed to reap auxiliary processes")
	}

	log.Info("guestinit successfully exiting")
}
