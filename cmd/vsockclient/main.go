package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

const (
	defaultPort   = 4032
	stateDir      = "./vm-state"
	vsockFileName = "vsock.sock"
)

func getVsockPath(vmName string) string {
	return path.Join(stateDir, vmName, vsockFileName)
}

func startInteractiveSession(socketPath string, port int) error {
	// Connect to Unix domain socket
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return fmt.Errorf("failed to connect to socket %s: %v", socketPath, err)
	}
	defer conn.Close()

	// Send CONNECT command
	connectCmd := fmt.Sprintf("CONNECT %d\n", port)
	_, err = conn.Write([]byte(connectCmd))
	if err != nil {
		return fmt.Errorf("failed to send CONNECT command: %v", err)
	}

	// Read response to CONNECT
	reader := bufio.NewReader(conn)
	response, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read CONNECT response: %v", err)
	}

	response = strings.TrimSpace(response)
	if !strings.HasPrefix(response, "OK") {
		return fmt.Errorf("unexpected response to CONNECT: %s", response)
	}

	// Start interactive session
	fmt.Println("Connected to vsock server. Enter commands (Ctrl+C to exit):")

	// Create a channel to handle server responses
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				if err != io.EOF {
					log.Errorf("Error reading from server: %v", err)
				}
				return
			}
			fmt.Print(line)
		}
	}()

	// Read commands from stdin and send to server
	stdinReader := bufio.NewReader(os.Stdin)
	for {
		cmd, err := stdinReader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return fmt.Errorf("error reading from stdin: %v", err)
		}

		_, err = conn.Write([]byte(cmd))
		if err != nil {
			return fmt.Errorf("error sending command: %v", err)
		}
	}

	return nil
}

func main() {
	app := &cli.App{
		Name:  "vsockclient",
		Usage: "Interactive client for VM's vsockserver via Unix domain socket",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "vm",
				Aliases:  []string{"v"},
				Usage:    "Name of the VM to connect to",
				Required: true,
			},
			&cli.IntFlag{
				Name:    "port",
				Aliases: []string{"p"},
				Usage:   "Port number to connect to",
				Value:   defaultPort,
			},
		},
		Action: func(c *cli.Context) error {
			vmName := c.String("vm")
			port := c.Int("port")

			socketPath := getVsockPath(vmName)
			if _, err := os.Stat(socketPath); os.IsNotExist(err) {
				return fmt.Errorf("vsock socket not found for VM %s at %s", vmName, socketPath)
			}

			log.WithFields(log.Fields{
				"vm":     vmName,
				"port":   port,
				"socket": socketPath,
			}).Info("Starting interactive session")

			return startInteractiveSession(socketPath, port)
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
