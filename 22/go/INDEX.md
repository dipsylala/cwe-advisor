# CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Go

## LLM Guidance

Path Traversal in Go usually appears when request or config data reaches `os.Open`, `os.ReadFile`, or `http.ServeFile` via string concatenation or an unchecked `filepath.Join`. `filepath.Clean` and `filepath.Join` only normalize path syntax - they resolve `.`/`..` sequences but do not enforce that the result stays inside an allowed directory, so a boundary check is still required. Prefer indirect reference maps or Go 1.24+ `os.Root`/`os.OpenInRoot` for traversal-resistant access; otherwise clean, join against a fixed base, and verify containment before opening.

## Key Principles

- Never build file paths via string concatenation with user input; treat any `filepath.Join` result as untrusted until validated
- `filepath.Clean`/`filepath.Join` normalize syntax only - do not mistake normalization for a security boundary check
- After joining and cleaning, verify the resulting absolute path is contained within the base directory using `strings.HasPrefix(full, base+string(filepath.Separator))`
- Resolve symlinks with `filepath.EvalSymlinks` before opening when the directory may contain attacker-influenced links, or reject non-regular files with `os.Lstat`/`Mode().IsRegular()`
- Prefer indirect references: map a user-supplied ID to a safe path through a Go `map` or database lookup instead of deriving any path from raw input
- Where available, use Go 1.24+ `os.Root`/`os.OpenInRoot` for file access rooted at a directory, which resists traversal even through symlinks
- Archive extraction (Zip Slip): treat `archive/zip` and `archive/tar` entry `Name` fields as untrusted - join with `filepath.Join`, clean, and apply the same base-directory containment check as any other path (or reject with Go 1.20+ `filepath.IsLocal`) before creating the file; reject entries with `..` or absolute paths

## Remediation Steps

- Locate - find file-serving/reading sinks: `os.Open`, `os.ReadFile`, `os.Create`, `http.ServeFile`, `os.DirFS`
- Trace data flow - identify where request, query, or header data reaches path construction (`filepath.Join`, string concatenation)
- Replace the unsafe pattern - use an indirect lookup where feasible, otherwise `filepath.Clean` plus `filepath.Join` against a fixed base directory
- Bind, encode, validate, or authorize - reject absolute paths (`filepath.IsAbs`) and inputs starting with `..` before joining
- Break taint after allowlist validation - after the boundary check passes, use only the canonicalized path variable for the file operation, never the original input
- Harden configuration - use `os.Lstat` plus `IsRegular()`, or `os.Root`/`os.OpenInRoot` (Go 1.24+), to avoid symlink-based escapes; restrict filesystem permissions on the served directory
- Test - verify with `../` sequences, absolute paths, encoded traversal, and symlink escape attempts

## Safe Pattern

```go
// SAFE: Canonicalize, then enforce base-directory containment
package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

func safeOpen(baseDir, userInput string) (*os.File, error) {
	base, err := filepath.Abs(baseDir)
	if err != nil {
		return nil, err
	}
	clean := filepath.Clean(userInput)
	if filepath.IsAbs(clean) || strings.HasPrefix(clean, "..") {
		return nil, errors.New("invalid path")
	}
	full := filepath.Join(base, clean)
	if full != base && !strings.HasPrefix(full, base+string(filepath.Separator)) {
		return nil, errors.New("path traversal detected")
	}
	// If this pattern uses an allowlist, pass the allowlist-selected value to the sink.
	return os.Open(full)
}
```
