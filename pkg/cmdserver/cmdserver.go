package cmdserver

// fileData represents a single file's content and metadata.
type FileData struct {
	Content string `json:"content"`
	Path    string `json:"path"`
	Error   string `json:"error,omitempty"`
}

// FilesGetResponse represents multiple files.
type FilesGetResponse struct {
	Files []FileData `json:"files"`
}

// FilePostData represents a single file to be uploaded.
type FilePostData struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// FilesPostRequest represents multiple files to be uploaded.
type FilesPostRequest struct {
	Files []FilePostData `json:"files"`
}

// RunCmdResponse structure for JSON responses from command execution
type RunCmdResponse struct {
	Output string `json:"output,omitempty"`
	Error  string `json:"error,omitempty"`
} 