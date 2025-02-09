package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

type runCmdRequest struct {
	Cmd string `json:"cmd"`
}

type runCmdResponse struct {
	Output string `json:"output,omitempty"`
	Error  string `json:"error,omitempty"`
}

func unixSocketHTTPClient(socketPath string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				log.Infof("Attempting to dial unix socket at %s", socketPath)
				return net.Dial("unix", socketPath)
			},
		},
	}
}

func runCommand(client *http.Client, cmd string) error {
	// Prepare the request
	reqBody := runCmdRequest{
		Cmd: cmd,
	}
	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %v", err)
	}

	// Create HTTP request
	req, err := http.NewRequest(http.MethodPost, "http://localhost/cmd", bytes.NewBuffer(jsonBody))
	if err != nil {
		return fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// Send request
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned error: %s", string(body))
	}

	// Parse response
	var cmdResp runCmdResponse
	if err := json.Unmarshal(body, &cmdResp); err != nil {
		return fmt.Errorf("failed to parse response: %v", err)
	}

	// Handle response
	if cmdResp.Error != "" {
		return fmt.Errorf("command failed: %s\nOutput: %s", cmdResp.Error, cmdResp.Output)
	}

	fmt.Print(cmdResp.Output)
	return nil
}

func main() {
	app := &cli.App{
		Name:  "cmdclient",
		Usage: "Send commands to a VM's cmdserver via Unix domain socket",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "uds",
				Usage:    "Path to the Unix domain socket (AF_UNIX) to connect to",
				Required: true,
			},
		},
		Action: func(c *cli.Context) error {
			udsPath := c.String("uds")
			if c.NArg() == 0 {
				return fmt.Errorf("command argument required")
			}

			client := unixSocketHTTPClient(udsPath)

			cmd := strings.Join(c.Args().Slice(), " ")
			if err := runCommand(client, cmd); err != nil {
				log.Fatal(err)
			}

			return nil
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
