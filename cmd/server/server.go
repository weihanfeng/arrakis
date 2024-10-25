package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"strings"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/abshkbh/chv-lambda/cmd/server/fountain"
	"github.com/abshkbh/chv-lambda/cmd/server/ipallocator"
	"github.com/abshkbh/chv-lambda/openapi"
	"github.com/abshkbh/chv-lambda/out/protos"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	numBootVcpus    = 1
	memorySizeBytes = 512 * 1024 * 1024
	// Case sensitive.
	serialPortMode = "Tty"
	// Case sensitive.
	consolePortMode = "Off"
	chvBinPath      = "/home/maverick/projects/chv-lambda/resources/bin/cloud-hypervisor"

	bridgeName              = "br0"
	bridgeIP                = "10.20.1.1/24"
	bridgeSubnet            = "10.20.1.0/24"
	numNetDeviceQueues      = 2
	netDeviceQueueSizeBytes = 256
	netDeviceId             = "_net0"
	stateDir                = "/run/chv-lambda"
)

var (
	kernelPath = "resources/bin/compiled-vmlinux.bin"
	rootfsPath = "out/ubuntu-ext4.img"
	initPath   = "/usr/bin/tini -- /opt/custom_scripts/guestinit"
)

func String(s string) *string {
	return &s
}

func Int32(i int32) *int32 {
	return &i
}

type vm struct {
	name          string
	stateDirPath  string
	apiSocketPath string
	apiClient     *openapi.APIClient
	process       *os.Process
	ip            *net.IPNet
}

func getKernelCmdLine(gatewayIP string, guestIP string, entryPoint string) string {
	return fmt.Sprintf(
		"console=ttyS0 gateway_ip=\"%s\" guest_ip=\"%s\" root=/dev/vda rw entry_point=\"%s\" init=%s",
		gatewayIP,
		guestIP,
		entryPoint,
		initPath,
	)
}

// bridgeExists checks if a bridge with the given name exists.
func bridgeExists(bridgeName string) (bool, error) {
	cmd := exec.Command("ip", "link", "show", "type", "bridge")
	output, err := cmd.Output()
	if err != nil {
		return false, fmt.Errorf("error executing command: %v", err)
	}

	bridges := strings.Split(string(output), "\n")

	for _, bridge := range bridges {
		if strings.Contains(bridge, bridgeName+":") {
			return true, nil
		}
	}

	return false, nil
}

// setupBridgeAndFirewall sets up a bridge and firewall rules for the given bridge name, IP address, and subnet.
func setupBridgeAndFirewall(backupFile string, bridgeName string, bridgeIP string, bridgeSubnet string) error {
	output, err := exec.Command("iptables-save").Output()
	if err != nil {
		return fmt.Errorf("failed to run iptables-save: %w", err)
	}

	err = os.WriteFile(backupFile, output, 0644)
	if err != nil {
		return fmt.Errorf("failed to save iptables-save to: %v: %w", backupFile, err)
	}

	// Get default network interface
	output, err = exec.Command("sh", "-c", "ip r | grep default | awk '{print $5}'").Output()
	if err != nil {
		return fmt.Errorf("failed to get default network interface: %w", err)
	}
	hostDefaultNetworkInterface := strings.TrimSpace(string(output))

	exists, err := bridgeExists(bridgeName)
	if err != nil {
		return fmt.Errorf("failed to detect if bridge exists: %w", err)
	}

	if exists {
		log.Info("networking already setup")
		return nil
	}

	// Setup bridge and firewall rules
	commands := []struct {
		name string
		args []string
	}{
		{"ip", []string{"l", "add", bridgeName, "type", "bridge"}},
		{"ip", []string{"l", "set", bridgeName, "up"}},
		{"ip", []string{"a", "add", bridgeIP, "dev", bridgeName, "scope", "host"}},
		{"iptables", []string{"-t", "nat", "-A", "POSTROUTING", "-s", bridgeSubnet, "-o", hostDefaultNetworkInterface, "-j", "MASQUERADE"}},
		{"sysctl", []string{"-w", fmt.Sprintf("net.ipv4.conf.%s.forwarding=1", hostDefaultNetworkInterface)}},
		{"sysctl", []string{"-w", fmt.Sprintf("net.ipv4.conf.%s.forwarding=1", bridgeName)}},
		{"iptables", []string{"-t", "filter", "-I", "FORWARD", "-s", bridgeSubnet, "-j", "ACCEPT"}},
		{"iptables", []string{"-t", "filter", "-I", "FORWARD", "-d", bridgeSubnet, "-j", "ACCEPT"}},
	}

	for _, cmd := range commands {
		if err := exec.Command(cmd.name, cmd.args...).Run(); err != nil {
			return fmt.Errorf("failed to execute command '%s %s': %w", cmd.name, strings.Join(cmd.args, " "), err)
		}
	}

	return nil
}

func getVmStateDirPath(vmName string) string {
	return path.Join(stateDir, vmName)
}

func getVmSocketPath(vmStateDir string, vmName string) string {
	return path.Join(vmStateDir, vmName+".sock")
}

func unixSocketClient(socketPath string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		},
		Timeout: time.Second * 30,
	}
}

func createApiClient(apiSocketPath string) *openapi.APIClient {
	configuration := openapi.NewConfiguration()
	configuration.HTTPClient = unixSocketClient(apiSocketPath)
	configuration.Servers = openapi.ServerConfigurations{
		{
			URL: "http://localhost/api/v1",
		},
	}
	return openapi.NewAPIClient(configuration)
}

func waitForServer(ctx context.Context, apiClient *openapi.APIClient, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		for {
			select {
			case <-ctx.Done():
				errCh <- ctx.Err()
				return
			default:
				resp, r, err := apiClient.DefaultAPI.VmmPingGet(ctx).Execute()
				if err == nil {
					log.WithFields(log.Fields{
						"buildVersion": *resp.BuildVersion,
						"statusCode":   r.StatusCode,
					}).Info("cloud-hypervisor server up")
					errCh <- nil
					return
				}
				time.Sleep(10 * time.Millisecond)
			}
		}
	}()

	return <-errCh
}

func reapVMProcess(vm *vm, logger *log.Entry, timeout time.Duration) error {
	done := make(chan error, 1)
	go func() {
		_, err := vm.process.Wait()
		done <- err
	}()

	select {
	case err := <-done:
		logger.Infof("VM process exited via wait")
		return err
	case <-time.After(timeout):
		logger.Warnf("Timeout waiting for VM process to exit")
	}

	// Attempt to kill the process if it's still running. This should also
	// trigger the wait in the goroutine preventing it's leak.
	err := vm.process.Kill()
	if err != nil {
		return fmt.Errorf("failed to kill VM process: %v", err)
	}
	return fmt.Errorf("VM process was force killed after timeout")
}

func (s *server) createVM(ctx context.Context, vmName string, entryPoint string) error {
	vmStateDir := getVmStateDirPath(vmName)
	err := os.MkdirAll(vmStateDir, 0755)
	if err != nil {
		return fmt.Errorf("failed to create vm state dir: %w", err)
	}
	log.Infof("CREATED: %v", vmStateDir)

	apiSocketPath := getVmSocketPath(vmStateDir, vmName)
	apiClient := createApiClient(apiSocketPath)

	logFilePath := path.Join(vmStateDir, "log")
	logFile, err := os.Create(logFilePath)
	if err != nil {
		return fmt.Errorf("failed to create log file: %w", err)
	}

	tapDevice, err := s.fountain.CreateTapDevice(vmName)
	if err != nil {
		return fmt.Errorf("failed to create tap device: %w", err)
	}

	cmd := exec.Command(chvBinPath, "--api-socket", apiSocketPath)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	// Add VMs to a separate process group. Otherwise Ctrl-C goes to the VMs
	// without us handling it. Now we can handle it and gracefully shut down
	// each VM.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	err = cmd.Start()
	if err != nil {
		return fmt.Errorf("error spawning vm: %w", err)
	}

	err = waitForServer(ctx, apiClient, 10*time.Second)
	if err != nil {
		return fmt.Errorf("error waiting for vm: %w", err)
	}
	log.WithField("vmname", vmName).Infof("VM started PID:%d", cmd.Process.Pid)

	guestIP, err := s.ipAllocator.AllocateIP()
	if err != nil {
		return fmt.Errorf("error allocating guest ip: %w", err)
	}
	log.Infof("Allocated IP: %v", guestIP)

	vmConfig := openapi.VmConfig{
		Payload: openapi.PayloadConfig{
			Kernel:  String(kernelPath),
			Cmdline: String(getKernelCmdLine(bridgeIP, guestIP.String(), entryPoint)),
		},
		Disks:   []openapi.DiskConfig{{Path: rootfsPath}},
		Cpus:    &openapi.CpusConfig{BootVcpus: numBootVcpus, MaxVcpus: numBootVcpus},
		Memory:  &openapi.MemoryConfig{Size: memorySizeBytes},
		Serial:  openapi.NewConsoleConfig(serialPortMode),
		Console: openapi.NewConsoleConfig(consolePortMode),
		Net:     []openapi.NetConfig{{Tap: String(tapDevice), NumQueues: Int32(numNetDeviceQueues), QueueSize: Int32(netDeviceQueueSizeBytes), Id: String(netDeviceId)}},
	}
	req := apiClient.DefaultAPI.CreateVM(ctx)
	req = req.VmConfig(vmConfig)

	// Execute the request
	resp, err := req.Execute()
	if err != nil {
		return fmt.Errorf("failed to start VM: %w", err)
	}

	if resp.StatusCode != 200 && resp.StatusCode != 204 {
		return fmt.Errorf("failed to start VM. bad status: %v", resp)
	}

	resp, err = apiClient.DefaultAPI.BootVM(ctx).Execute()
	if err != nil {
		return fmt.Errorf("failed to boot VM resp.Body: %v: %w", resp.Body, err)
	}

	if resp.StatusCode != 200 && resp.StatusCode != 204 {
		return fmt.Errorf("failed to boot VM. bad status: %v", resp)
	}

	vm := &vm{
		name:          vmName,
		stateDirPath:  vmStateDir,
		apiSocketPath: apiSocketPath,
		apiClient:     apiClient,
		process:       cmd.Process,
		ip:            guestIP,
	}
	log.Infof("Successfully created VM: %s", vmName)
	s.vms[vmName] = vm
	return nil
}

type server struct {
	protos.UnimplementedVMManagementServiceServer
	vms         map[string]*vm
	fountain    *fountain.Fountain
	ipAllocator *ipallocator.IPAllocator
	sigChan     chan os.Signal
}

func (s *server) StartVM(ctx context.Context, req *protos.VMRequest) (*protos.VMResponse, error) {
	vmName := req.GetVmName()
	entryPoint := req.GetEntryPoint()
	logger := log.WithField("vmName", vmName)
	logger.Infof("received request to start VM")

	vm, exists := s.vms[vmName]
	if exists {
		resp, err := vm.apiClient.DefaultAPI.BootVM(ctx).Execute()
		if err != nil {
			return nil, fmt.Errorf("failed to boot existing VM resp.Body: %v: %w", resp.Body, err)
		}

		if resp.StatusCode >= 300 {
			return nil, fmt.Errorf("failed to boot existing VM. bad status: %v", resp)
		}
	} else {
		err := s.createVM(ctx, vmName, entryPoint)
		if err != nil {
			logger.Errorf("failed to start: %v", err)
			return nil, err
		}
	}

	logger.Infof("VM started")
	return &protos.VMResponse{}, nil
}

func (s *server) StopVM(ctx context.Context, req *protos.VMRequest) (*protos.VMResponse, error) {
	vmName := req.GetVmName()
	log.WithField("vmName", vmName).Infof("received request to stop VM")

	vm, exists := s.vms[vmName]
	if !exists {
		return nil, status.Errorf(codes.NotFound, "vm %s not found", vmName)
	}

	shutdown_req := vm.apiClient.DefaultAPI.ShutdownVM(ctx)
	resp, err := shutdown_req.Execute()
	if err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("Failed to stop VM: %v", err))
	}

	if resp.StatusCode != 200 && resp.StatusCode != 204 {
		return nil, status.Error(codes.Internal, fmt.Sprintf("failed to stop VM. bad status: %v", resp))
	}

	return &protos.VMResponse{}, nil
}

func (s *server) destroyVM(ctx context.Context, vmName string) error {
	log.WithField("vmName", vmName).Info("destroyVM")
	logger := log.WithField("vmName", vmName)

	vm, exists := s.vms[vmName]
	if !exists {
		return status.Errorf(codes.NotFound, "vm %s not found", vmName)
	}

	// Shutdown for a graceful exit before full deletion. Don't error out if this fails as we still
	// want to try a deletion after this.
	shutdownReq := vm.apiClient.DefaultAPI.ShutdownVM(ctx)
	resp, err := shutdownReq.Execute()
	if err != nil {
		logger.Warnf("failed to shutdown VM before deleting: %v", err)
	} else if resp.StatusCode >= 300 {
		logger.Warnf("failed to shutdown VM before deleting. bad status: %v", resp)
	}

	deleteReq := vm.apiClient.DefaultAPI.DeleteVM(ctx)
	resp, err = deleteReq.Execute()
	if err != nil {
		return status.Error(codes.Internal, fmt.Sprintf("failed to delete VM: %v", err))
	}

	if resp.StatusCode >= 300 {
		return status.Error(codes.Internal, fmt.Sprintf("failed to stop VM. bad status: %v", resp))
	}

	shutdownVMMReq := vm.apiClient.DefaultAPI.ShutdownVMM(ctx)
	resp, err = shutdownVMMReq.Execute()
	if err != nil {
		return status.Error(codes.Internal, fmt.Sprintf("failed to shutdown VMM: %v", err))
	}

	if resp.StatusCode >= 300 {
		return status.Error(codes.Internal, fmt.Sprintf("failed to shutdown VMM. bad status: %v", resp))
	}

	err = reapVMProcess(vm, logger, 20*time.Second)
	if err != nil {
		logger.Warnf("failed to reap VM process: %v", err)
	}

	// Once deleted remove its directory and remove it from the internal store of VMs.
	err = os.RemoveAll(vm.stateDirPath)
	if err != nil {
		log.Warnf("Failed to delete directory %s: %v", vm.stateDirPath, err)
	}

	err = s.fountain.DestroyTapDevice(vmName)
	if err != nil {
		log.Warnf("failed to destroy the tap device for vm: %s: %v", vmName, err)
	}

	err = s.ipAllocator.FreeIP(vm.ip.IP)
	if err != nil {
		log.Warnf("failed to free IP: %s: %v", vm.ip.IP.String(), err)
	}
	delete(s.vms, vmName)
	return nil
}

func (s *server) destroyAllVMs(ctx context.Context) error {
	log.Info("destroying all VMs")
	var finalErr error
	for _, vm := range s.vms {
		err := s.destroyVM(ctx, vm.name)
		if err != nil {
			log.Warnf("failed to destroy and clean up vm: %s", vm.name)
		}
		finalErr = errors.Join(finalErr, err)
	}
	return finalErr
}

func (s *server) DestroyVM(ctx context.Context, req *protos.VMRequest) (*protos.VMResponse, error) {
	log.Infof("received request to destroy VM")
	vmName := req.GetVmName()
	err := s.destroyVM(ctx, vmName)
	if err != nil {
		return nil, err
	}
	return &protos.VMResponse{}, nil
}

func (s *server) DestroyAllVMs(ctx context.Context, req *protos.DestroyAllVMsRequest) (*protos.VMResponse, error) {
	log.Infof("received request to destroy all VMs")
	err := s.destroyAllVMs(ctx)
	if err != nil {
		return nil, err
	}
	return &protos.VMResponse{}, nil
}

func main() {
	err := os.MkdirAll(stateDir, 0755)
	if err != nil {
		log.WithError(err).Fatal("failed to create vm state dir")
	}

	ipBackupFile := fmt.Sprintf("/tmp/iptables-backup-%s.rules", time.Now().Format(time.UnixDate))
	err = setupBridgeAndFirewall(ipBackupFile, bridgeName, bridgeIP, bridgeSubnet)
	if err != nil {
		log.WithError(err).Fatal("failed to setup networking on the host")
	}

	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.WithError(err).Fatalf("failed to listen")
	}

	ipAllocator, err := ipallocator.NewIPAllocator(bridgeSubnet)
	if err != nil {
		log.WithError(err).Fatalf("failed to create ip allocator")
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	s := grpc.NewServer()
	apiServer := &server{
		vms:         make(map[string]*vm),
		fountain:    fountain.NewFountain(bridgeName),
		ipAllocator: ipAllocator,
		sigChan:     sigChan,
	}

	// Set up signal handler.
	go func() {
		log.Infof("waiting for signal")
		sig := <-apiServer.sigChan
		log.Infof("received signal: %v", sig)
		s.GracefulStop()
		log.Infof("gracefully stopped")
	}()

	protos.RegisterVMManagementServiceServer(s, apiServer)
	log.Printf("server PID:%d listening at %v", os.Getpid(), lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.WithError(err).Fatalf("failed to serve")
	}
	apiServer.destroyAllVMs(context.Background())
	log.WithError(err).Info("server exited")
}
