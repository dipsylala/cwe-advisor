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
- `multipart.FileHeader.Filename` is attacker-supplied and may contain path separators - take the base name at most as a display value, and store under a server-generated name

## Taint Sinks

`FileHeader.Filename`, `Header.Get("Content-Type")`, writes under an `http.FileServer` root

## Remediation Steps

- Locate - Find the handler that calls `r.FormFile()` or iterates `r.MultipartForm.File` to receive the upload
- Trace data flow - Follow the `Content-Type` header and `Filename` from `multipart.FileHeader` through to storage and any handler that serves the file back
- Replace the unsafe pattern - Remove any check that trusts the part's `Content-Type` header or the `Filename` extension as the sole gate
- Bind, encode, validate, or authorize - Read the opened file's leading bytes, call `http.DetectContentType`, and compare the result against an allowlist
- Break taint after allowlist validation - Use the detected content type and a generated filename for storage, not the client-supplied header or `Filename`; rewind with `file.Seek(0, io.SeekStart)` after sniffing and write with `os.OpenFile(..., os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)`
- Harden configuration - Enforce `http.MaxBytesReader` and an explicit `maxMemory` argument to `ParseMultipartForm`
- Test - Verify rejection of files with a mismatched extension/content-type and disallowed real content, oversized requests, and traversal sequences in `Filename`
