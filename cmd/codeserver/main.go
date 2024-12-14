package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/abshkbh/chv-lambda/pkg/config"

	log "github.com/sirupsen/logrus"
)

type codeServer struct {
}

type ExecuteRequest struct {
	Lang         string            `json:"lang"`
	Files        map[string]string `json:"files"`
	EntryPoint   string            `json:"entry_point"`
	Dependencies []string          `json:"dependencies"`
	Timeout      int               `json:"timeout"`
}

type ExecuteResponse struct {
	Output string `json:"output,omitempty"`
	Error  string `json:"error,omitempty"`
	Status string `json:"status"`
}

func (cs *codeServer) indexRoute(w http.ResponseWriter, r *http.Request) {
	response := map[string]string{
		"msg": "Hello from codeserver",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func (cs *codeServer) executePythonCode(req *ExecuteRequest, w http.ResponseWriter, r *http.Request) {
	tempDir, err := os.MkdirTemp("/tmp", "execute-*")
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to create temporary directory: %v", err.Error()), http.StatusInternalServerError)
		return
	}
	defer os.RemoveAll(tempDir)

	// Write files to the temporary directory
	for filename, content := range req.Files {
		filePath := filepath.Join(tempDir, filename)
		if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
			http.Error(w, fmt.Sprintf("failed to write file: %v", err.Error()), http.StatusInternalServerError)
			return
		}
	}

	// Install dependencies
	venvPythonPath := ""
	if len(req.Dependencies) > 0 {
		venvDir := filepath.Join(tempDir, "venv")

		// Create virtual environment
		cmd := exec.Command("python3", "-m", "venv", venvDir)
		if err := cmd.Run(); err != nil {
			http.Error(w, fmt.Sprintf("failed to create virtual environment: %v", err.Error()), http.StatusInternalServerError)
			return
		}

		// Activate virtual environment and install dependencies
		pipPath := filepath.Join(venvDir, "bin", "pip")
		cmd = exec.Command(pipPath, append([]string{
			"install",
			"--no-cache-dir",
		}, req.Dependencies...)...)

		if err := cmd.Run(); err != nil {
			http.Error(w, fmt.Sprintf("failed to install dependencies: %v", err.Error()), http.StatusInternalServerError)
			return
		}

		// Set the PATH to use the virtual environment's Python
		venvPythonPath = filepath.Join(venvDir, "bin", "python")
		os.Setenv("PATH", filepath.Join(venvDir, "bin")+":"+os.Getenv("PATH"))
	}

	// Execute the Python script
	var pythonPath string
	if venvPythonPath == "" {
		pythonPath = "python3"
	} else {
		pythonPath = venvPythonPath
	}
	cmd := exec.Command(pythonPath, filepath.Join(tempDir, req.EntryPoint))
	cmd.Dir = tempDir

	outputChan := make(chan []byte)
	errorChan := make(chan error)
	go func() {
		output, err := cmd.CombinedOutput()
		if err != nil {
			errorChan <- err
		} else {
			outputChan <- output
		}
	}()

	select {
	case output := <-outputChan:
		response := ExecuteResponse{
			Output: string(output),
			Status: "success",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)

	case err := <-errorChan:
		response := ExecuteResponse{
			Error:  "Execution error: " + err.Error(),
			Status: "error",
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(response)

	case <-time.After(time.Duration(req.Timeout) * time.Second):
		cmd.Process.Kill()
		response := ExecuteResponse{
			Error:  "Execution timed out",
			Status: "timeout",
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusRequestTimeout)
		json.NewEncoder(w).Encode(response)
	}
}

func (cs *codeServer) executeTypescriptCode(req *ExecuteRequest, w http.ResponseWriter, r *http.Request) {
	// TODO: Unimplemented.
}

func (cs *codeServer) executeRoute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ExecuteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("failed to decode request: %v", err.Error()), http.StatusBadRequest)
		return
	}

	lang := strings.ToLower(req.Lang)
	if lang != "python" && lang != "typescript" {
		http.Error(w, fmt.Sprintf("unsupported language: %s", lang), http.StatusBadRequest)
		return
	}

	if lang == "python" {
		cs.executePythonCode(&req, w, r)
	} else {
		cs.executeTypescriptCode(&req, w, r)
	}

}

func initializeRoutes(cs *codeServer) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", cs.indexRoute)
	mux.HandleFunc("POST /execute", cs.executeRoute)
	return mux
}

func main() {
	log.Info("starting codeserver...")
	cs := &codeServer{}
	router := initializeRoutes(cs)

	server := &http.Server{
		Addr:    config.CodeServerPort,
		Handler: router,
	}

	err := server.ListenAndServe()
	if err != nil {
		log.WithError(err).Errorf("codeserver exited with: %v", err)
	}
}
