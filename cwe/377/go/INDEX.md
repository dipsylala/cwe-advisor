# CWE-377: Insecure Temporary File - Go

## LLM Guidance

Insecure temporary files in Go usually come from manually building paths with `fmt.Sprintf` or `filepath.Join` plus a predictable name (timestamps, PIDs, fixed strings) under `/tmp` or `os.TempDir()`, or from widening permissions after creation with a separate `os.Chmod` call. The fix is `os.CreateTemp` (Go 1.16+; the older `ioutil.TempFile` is deprecated but equivalent) and `os.MkdirTemp`, which atomically create a file or directory with a cryptographically random name and mode 0600/0700, closing the race-condition and permission-window issues in one call.

## Key Principles

- Use `os.CreateTemp(dir, pattern)` or `os.MkdirTemp(dir, pattern)` for all temp file/directory creation; never construct temp paths with `fmt.Sprintf` plus `os.Create` or `os.OpenFile`
- Do not set permissions in a follow-up `os.Chmod` call; `os.CreateTemp` applies 0600 atomically at creation, avoiding the window where a manually created file sits at a broader default mode
- Pass an empty string as the `dir` argument to use the directory `os.TempDir()` returns - `$TMPDIR` on Unix, falling back to `/tmp`, or `%TMP%`/`%TEMP%`/`%USERPROFILE%` in that order on Windows - or an application-owned subdirectory created with `os.MkdirAll(path, 0700)`
- Guarantee cleanup with `defer os.Remove(f.Name())` (or `defer os.RemoveAll(dir)` for directories) immediately after the creation check, including in tests via `t.Cleanup`
- Never derive a second temp file's path by string-manipulating a securely created file's name (e.g., swapping the extension); create each temp file independently through `os.CreateTemp`
- For highly sensitive contents, encrypt data before writing it to the temp file as defense-in-depth beyond permission restrictions
- `os.MkdirAll` on a path meant to be private succeeds silently if the directory already exists (possibly attacker-planted), skipping the permission you asked for; use `os.Mkdir` (which fails on an existing path) followed by an `os.Lstat` ownership/mode check, or `os.MkdirTemp` when the name doesn't need to be reused

## Taint Sinks

`os.Create()`/`os.OpenFile()` with `fmt.Sprintf("/tmp/...")`, manual `filepath.Join(os.TempDir(), ...)`, `os.Chmod()` after creation, `os.MkdirAll` on a path meant to be exclusive

## Remediation Steps

- Locate - Find manual temp path construction (`filepath.Join(os.TempDir(), ...)`, `fmt.Sprintf("/tmp/...")`) and any `os.Create`/`os.OpenFile` calls targeting those paths
- Trace data flow - Confirm whether the file holds sensitive data (credentials, PII, session data) and whether cleanup runs on all exit paths, including errors and panics
- Replace the unsafe pattern - Swap manual path building and `os.Create` for `os.CreateTemp(dir, "prefix-*.ext")`, or `os.MkdirTemp` for a temp directory of related files
- Bind, encode, validate, or authorize - Not applicable beyond ensuring the returned `*os.File`/path is used directly rather than recomputed
- Harden configuration - Remove any separate `os.Chmod` widening the mode; verify the target `dir` argument itself has restrictive permissions if using a custom subdirectory
- Test - Verify file permissions are 0600 with `os.Stat`, confirm filenames are non-deterministic across runs, and confirm the file is removed after normal completion, early return, and panic (recover) paths
