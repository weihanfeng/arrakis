package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/coreos/go-systemd/daemon"
	"github.com/mdlayher/vsock"
	log "github.com/sirupsen/logrus"
)

const (
	// Define a base directory to prevent path traversal.
	baseDir = "/tmp/vsockserver"
	port    = 4032
)

func handleConnection(conn *vsock.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)

	for {
		// Read command from the connection
		cmd, err := reader.ReadString('\n')
		if err != nil {
			if err != io.EOF {
				log.Errorf("Error reading from connection: %v", err)
			}
			return
		}

		// Trim whitespace and newline
		cmd = strings.TrimSpace(cmd)

		if cmd == "" {
			continue
		}

		// Set up environment variables with a restricted PATH for security
		// This limits command execution to only system binaries in standard locations:
		// - /usr/local/bin: For locally compiled/installed programs
		// - /usr/bin: For distribution-packaged programs
		// - /bin: For essential system binaries
		// Prevents execution of programs from unsafe locations like current directory,
		// home directories, or other non-standard paths that could contain malicious code
		env := os.Environ()
		customPath := "/usr/local/bin:/usr/bin:/bin"
		env = append(env, "PATH="+customPath)

		// Create and configure the command
		command := exec.Command("/bin/bash", "-c", cmd)
		command.Env = env
		command.Dir = baseDir

		// Log the command execution
		log.WithFields(log.Fields{
			"cmd":        cmd,
			"workingDir": command.Dir,
		}).Info("Executing command")

		// Execute the command and capture output
		output, err := command.CombinedOutput()
		if err != nil {
			errMsg := fmt.Sprintf("Error: %v\nOutput: %s\n", err, string(output))
			log.WithFields(log.Fields{
				"cmd":    cmd,
				"error":  err,
				"output": string(output),
			}).Error("Command execution failed")
			conn.Write([]byte(errMsg))
			continue
		}

		// Log successful execution
		log.WithFields(log.Fields{
			"cmd":    cmd,
			"output": string(output),
		}).Info("Command executed successfully")

		// Write the output back to the connection
		_, err = conn.Write(append(output, '\n'))
		if err != nil {
			log.Errorf("Error writing response: %v", err)
			return
		}
	}
}

func main() {
	listener, err := vsock.Listen(uint32(port), &vsock.Config{})
	if err != nil {
		log.Fatalf("Failed to create vsock listener: %v", err)
	}
	defer listener.Close()

	log.Printf("VSock server listening on port %d...", port)
	// Make other services start via systemd since we're ready to debug.
	if _, err := daemon.SdNotify(false, daemon.SdNotifyReady); err != nil {
		log.Warnf("Failed to notify systemd of readiness: %v", err)
	}

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Errorf("Failed to accept connection: %v", err)
			continue
		}

		// Handle each connection in a goroutine
		go handleConnection(conn.(*vsock.Conn))
	}
}
