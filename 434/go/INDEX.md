# CWE-434: Unrestricted Upload of File with Dangerous Type - Go

## LLM Guidance

Go's `net/http` exposes uploads through `multipart.FileHeader` after `r.ParseMultipartForm()`. The common mistake is trusting `FileHeader.Header.Get("Content-Type")` or the extension of `FileHeader.Filename`, both of which are supplied by the client in the multipart part headers and not verified by the standard library. Detect the real content type server-side with `http.DetectContentType`, which reads the file's leading bytes, and generate the stored filename instead of using the client-supplied one.

## Key Principles

- Do not trust `FileHeader.Header.Get("Content-Type")` or the extension of `FileHeader.Filename` - both are client-supplied multipart part metadata
- Call `http.DetectContentType()` on the first 512 bytes of the opened file to determine the real content type, and check it against an allowlist
- Call `r.ParseMultipartForm(maxMemory)` with an explicit `maxMemory` and additionally guard with `http.MaxBytesReader(w, r.Body, maxBytes)` before parsing, so an oversized request is rejected early rather than exhausting memory or disk
- Generate the stored filename (e.g., with `crypto/rand` or a UUID library) instead of using `FileHeader.Filename`, which may contain path separators or traversal sequences
- Store uploaded files outside any directory served by `http.FileServer` or `http.Dir`; serve them back through a handler that streams from private storage
- Use `filepath.Clean` and `filepath.Join` cautiously and verify the resulting path stays within the intended storage directory before writing

## Remediation Steps

- Locate - Find the handler that calls `r.FormFile()` or iterates `r.MultipartForm.File` to receive the upload
- Trace data flow - Follow the `Content-Type` header and `Filename` from `multipart.FileHeader` through to storage and any handler that serves the file back
- Replace the unsafe pattern - Remove any check that trusts the part's `Content-Type` header or the `Filename` extension as the sole gate
- Bind, encode, validate, or authorize - Read the opened file's leading bytes, call `http.DetectContentType`, and compare the result against an allowlist
- Break taint after allowlist validation - Use the detected content type and a generated filename for storage, not the client-supplied header or `Filename`
- Harden configuration - Enforce `http.MaxBytesReader` and an explicit `maxMemory` argument to `ParseMultipartForm`
- Test - Verify rejection of files with a mismatched extension/content-type and disallowed real content, oversized requests, and traversal sequences in `Filename`

## Safe Pattern

```go
// SAFE: content-sniffed validation via http.DetectContentType, generated filename, storage outside webroot
package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

var allowedTypes = map[string]string{
	"image/png":  ".png",
	"image/jpeg": ".jpg",
}

const uploadDir = "/var/app-data/uploads" // outside any http.FileServer root

func uploadHandler(w http.ResponseWriter, r *http.Request) {
	const maxBytes = 5 << 20 // 5 MB
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)

	if err := r.ParseMultipartForm(maxBytes); err != nil {
		http.Error(w, "request too large or malformed", http.StatusBadRequest)
		return
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "missing file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// SAFE: detect real type from bytes, not the client-supplied Content-Type header
	buf := make([]byte, 512)
	n, _ := io.ReadFull(file, buf)
	detectedType := http.DetectContentType(buf[:n])

	ext, ok := allowedTypes[detectedType]
	if !ok {
		http.Error(w, fmt.Sprintf("unsupported file type: %s", detectedType), http.StatusBadRequest)
		return
	}

	nameBytes := make([]byte, 16)
	if _, err := rand.Read(nameBytes); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	storedName := hex.EncodeToString(nameBytes) + ext
	targetPath := filepath.Join(uploadDir, storedName)

	out, err := os.OpenFile(targetPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		http.Error(w, "failed to store file", http.StatusInternalServerError)
		return
	}
	defer out.Close()

	if _, err := file.Seek(0, io.SeekStart); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if _, err := io.Copy(out, file); err != nil {
		http.Error(w, "failed to store file", http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "stored as %s", storedName)
}
```
