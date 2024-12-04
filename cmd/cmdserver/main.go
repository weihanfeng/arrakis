package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/gorilla/mux"
	"github.com/mattn/go-shellwords"
)

const (
	// Define a base directory to prevent path traversal
	baseDir = "/tmp/server_files"
)

// RunCmdResponse structure for JSON responses
type RunCmdResponse struct {
	Output string `json:"output,omitempty"`
	Error  string `json:"error,omitempty"`
}

// Handler for POST /upload_file
// Expects JSON body with "src" and "dst"
func uploadFileHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		log.WithField("api", "upload").Error("method not allowed")
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		FilePathToContent map[string]string `json:"file_path_to_content"`
	}

	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		log.WithField("api", "upload").Error("invalid json body")
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	for relativeFilePath, content := range req.FilePathToContent {
		absoluteFilePath := filepath.Join(baseDir, relativeFilePath)

		// Create any necessary parent directories
		err := os.MkdirAll(filepath.Dir(absoluteFilePath), fs.ModePerm)
		if err != nil {
			log.WithField("api", "upload").Errorf("failed to create dir for: %s err: %v", absoluteFilePath, err)
			http.Error(w, fmt.Sprintf("failed to create dir for: %s err: %v", absoluteFilePath, err), http.StatusInternalServerError)
			return
		}

		// Create the file and write the content
		file, err := os.Create(absoluteFilePath)
		if err != nil {
			log.WithField("api", "upload").Errorf("failed to create file: %s err: %v", absoluteFilePath, err)
			http.Error(w, fmt.Sprintf("failed to create file: %s err: %v", absoluteFilePath, err), http.StatusInternalServerError)
			return
		}
		defer file.Close()

		_, err = file.WriteString(content)
		if err != nil {
			log.WithField("api", "upload").Errorf("failed to write file: %s err: %v", absoluteFilePath, err)
			http.Error(w, fmt.Sprintf("failed to write file: %s err: %v", absoluteFilePath, err), http.StatusInternalServerError)
			return
		}
	}
}

// Handler for GET /download_file
// Expects "src" as query parameter
func downloadFileHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	src := r.URL.Query().Get("src")
	if src == "" {
		http.Error(w, "Missing 'src' query parameter", http.StatusBadRequest)
		return
	}

	// Resolve path to prevent path traversal
	filePath := filepath.Join(baseDir, filepath.Clean(src))

	// Check if file exists and is not a directory
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		http.Error(w, "File does not exist", http.StatusBadRequest)
		return
	}
	if fileInfo.IsDir() {
		http.Error(w, "Requested file is a directory", http.StatusBadRequest)
		return
	}

	// Serve the file
	http.ServeFile(w, r, filePath)
}

// Handler for POST /run_command
// Expects JSON body with "cmd"
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
		resp := RunCmdResponse{
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
	resp := RunCmdResponse{
		Output: string(output),
	}
	writeJSON(w, resp)

}

// Utility function to write JSON response
func writeJSON(w http.ResponseWriter, resp RunCmdResponse) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func main() {
	// Ensure base directory exists
	err := os.MkdirAll(baseDir, os.ModePerm)
	if err != nil {
		log.Fatalf("Failed to create base directory: %v", err)
	}

	// Initialize Gorilla Mux router
	router := mux.NewRouter()

	// Register routes with their respective handlers
	router.HandleFunc("/upload_file", uploadFileHandler).Methods(http.MethodPost)
	router.HandleFunc("/download_file", downloadFileHandler).Methods(http.MethodGet)
	router.HandleFunc("/run_command", runCommandHandler).Methods(http.MethodPost)

	// Optionally, add logging middleware
	router.Use(loggingMiddleware)

	port := "8080"
	log.Printf("Server is running on port %s...", port)
	log.Fatal(http.ListenAndServe(":"+port, router))
}

// Optional: Middleware for logging requests
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[%s] %s %s", r.RemoteAddr, r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}
