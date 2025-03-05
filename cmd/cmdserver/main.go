package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/abshkbh/arrakis/pkg/cmdserver"
	"github.com/gorilla/mux"
	"github.com/mattn/go-shellwords"
)

const (
	// Define a base directory to prevent path traversal
	baseDir = "/tmp/server_files"
)

// uploadFileHandler handles "/files" POST requests.
func uploadFileHandler(w http.ResponseWriter, r *http.Request) {
	logger := log.WithField("api", "upload")
	if r.Method != http.MethodPost {
		logger.Error("method not allowed")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req cmdserver.FilesPostRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		logger.Error("invalid json body")
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	for _, file_data := range req.Files {
		if file_data.Path == "" {
			logger.Warn("skipping empty file path")
			continue
		}

		logger.Infof("uploading file: %s", file_data.Path)
		var absoluteFilePath string
		if filepath.IsAbs(file_data.Path) {
			absoluteFilePath = file_data.Path
		} else {
			absoluteFilePath = filepath.Join(baseDir, file_data.Path)
		}

		file, err := os.Create(absoluteFilePath)
		if err != nil {
			logger.Errorf("failed to create file: %s err: %v", absoluteFilePath, err)
			http.Error(w, fmt.Sprintf("failed to create file: %s err: %v", absoluteFilePath, err), http.StatusInternalServerError)
			return
		}
		defer file.Close()
		logger.Infof("uploading file: %s", absoluteFilePath)

		_, err = file.WriteString(file_data.Content)
		if err != nil {
			logger.Errorf("failed to write file: %s err: %v", absoluteFilePath, err)
			http.Error(w, fmt.Sprintf("failed to write file: %s err: %v", absoluteFilePath, err), http.StatusInternalServerError)
			return
		}
	}
}

// downloadFileHandler handles "/files" GET requests.
func downloadFileHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get files from query parameter, expects comma-separated paths
	filesParam := r.URL.Query().Get("paths")
	if filesParam == "" {
		http.Error(w, "Missing 'paths' query parameter", http.StatusBadRequest)
		return
	}

	filePaths := strings.Split(filesParam, ",")
	response := cmdserver.FilesGetResponse{
		Files: make([]cmdserver.FileData, 0, len(filePaths)),
	}

	for _, filePath := range filePaths {
		fileResp := cmdserver.FileData{Path: filePath}
		// Resolve path to prevent path traversal.
		absolutePath := filepath.Join(baseDir, filepath.Clean(filePath))
		content, err := os.ReadFile(absolutePath)
		if err != nil {
			fileResp.Error = fmt.Sprintf("Failed to read file: %v", err)
		} else {
			fileResp.Content = string(content)
		}
		log.WithField("api", "download").Infof("downloading file: %s", absolutePath)
		response.Files = append(response.Files, fileResp)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// runCommandHandler handles "/cmd" POST requests.
func runCommandHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		log.WithField("api", "run_cmd").Error("method not allowed")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Cmd string `json:"cmd"`
	}

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		log.WithField("api", "run_cmd").Error("invalid json body")
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	if strings.TrimSpace(req.Cmd) == "" {
		log.WithField("api", "run_cmd").Error("empty command")
		http.Error(w, "Empty Command", http.StatusBadRequest)
		return
	}

	// Parse the command string using shellwords to handle quotes and escaped spaces
	parser := shellwords.NewParser()
	parts, err := parser.Parse(req.Cmd)
	if err != nil {
		log.WithFields(log.Fields{
			"api": "run_cmd",
		}).Errorf("failed to parse command string: %v", err)
		http.Error(w, fmt.Sprintf("failed to parse command string: %v", err), http.StatusBadRequest)
		return
	}

	if len(parts) == 0 {
		log.WithFields(log.Fields{
			"api": "run_cmd",
		}).Error("empty command string")
		http.Error(w, "empty command string", http.StatusBadRequest)
		return
	}

	cmdName := parts[0]
	cmdArgs := parts[1:]

	// Set up environment variables
	env := os.Environ()
	customPath := "/usr/local/bin:/usr/bin:/bin" // Modify as needed
	env = append(env, "PATH="+customPath)

	// Create the command
	cmd := exec.Command("bash", "-c", req.Cmd)
	cmd.Env = env
	cmd.Dir = baseDir

	// Log the command execution details
	log.WithFields(log.Fields{
		"api":        "run_cmd",
		"cmd":        cmdName,
		"args":       cmdArgs,
		"workingDir": cmd.Dir,
	}).Info("Executing command")

	// Execute the command and capture the combined output
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.WithFields(log.Fields{
			"api":  "run_cmd",
			"cmd":  cmdName,
			"args": cmdArgs,
		}).Errorf("command execution failed output: %s err: %v", string(output), err)
		resp := cmdserver.RunCmdResponse{
			Error:  err.Error(),
			Output: string(output),
		}
		writeJSON(w, resp)
		return
	}

	// Log successful execution
	log.WithFields(log.Fields{
		"api":        "run_cmd",
		"cmd":        cmdName,
		"args":       cmdArgs,
		"output":     string(output),
		"workingDir": cmd.Dir,
	}).Info("command executed successfully")

	// Respond with the command output
	resp := cmdserver.RunCmdResponse{
		Output: string(output),
	}
	writeJSON(w, resp)
}

// indexHandler handles "/" GET requests.
func indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	response := map[string]string{
		"msg": "Hello from cmdserver",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Utility function to write JSON response
func writeJSON(w http.ResponseWriter, resp cmdserver.RunCmdResponse) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func main() {
	// Ensure base directory exists.
	err := os.MkdirAll(baseDir, os.ModePerm)
	if err != nil {
		log.Fatalf("Failed to create base directory: %v", err)
	}

	// Initialize Gorilla Mux router.
	router := mux.NewRouter()

	// Register routes with their respective handlers.
	router.HandleFunc("/", indexHandler).Methods(http.MethodGet)
	router.HandleFunc("/files", uploadFileHandler).Methods(http.MethodPost)
	router.HandleFunc("/files", downloadFileHandler).Methods(http.MethodGet)
	router.HandleFunc("/cmd", runCommandHandler).Methods(http.MethodPost)

	// Optionally, add logging middleware.
	router.Use(loggingMiddleware)

	port := "4031"
	log.Printf("Server is running on port %s...", port)
	log.Fatal(http.ListenAndServe(":"+port, router))
}

// Optional: Middleware for logging requests.
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[%s] %s %s", r.RemoteAddr, r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}
