# CWE-377: Insecure Temporary File - JavaScript

## LLM Guidance

Insecure temporary file creation in Node.js occurs when applications create files with predictable names, insecure permissions, or without proper cleanup in shared directories. Attackers can exploit race conditions, overwrite files, or access sensitive data. Use secure libraries like `tmp`, `temp`, or `fs.mkdtemp()` with proper permissions and automatic cleanup.

## Key Principles

- Use dedicated temporary file libraries (`tmp`, `temp`) or Node.js built-in `fs.mkdtemp()` with secure random naming
- Set restrictive file permissions using JavaScript octal literal `0o600` (POSIX mode `0600`) to prevent unauthorized access
- Ensure automatic cleanup of temporary files using library callbacks or process exit handlers
- Never create temporary files in world-writable directories with predictable names
- Validate and sanitize any user input used in temporary file operations
- `fs.mkdtemp()` creates a private *directory* atomically, which is the stronger primitive: files created inside it inherit its protection, so a per-run directory removes the per-file race entirely
- Do not build a name from `Math.random()` or a timestamp - it is guessable, and the guarantee that matters is that the name is generated and the file claimed in one operation
- Cleanup registered on `process.on('exit')` does not run on `SIGKILL` or `SIGSTOP`, and only runs on `SIGTERM`/`SIGINT` if you install a handler that exits; the `tmp` package's `removeCallback()`/`cleanupSync()` have the same limits, so treat cleanup as best-effort and keep the contents non-sensitive or encrypted
- Pass the mode at creation (`0o600`) rather than calling `fs.chmod()` afterwards, which leaves a window at the umask default

## Taint Sinks

`fs.writeFile('/tmp/...')` with a predictable name, `fs.open()` without the exclusive `wx` flag, hardcoded filenames under `os.tmpdir()`

## Remediation Steps

- Replace manual `fs.writeFile()` in `/tmp` with `tmp.file()` or `fs.mkdtemp()` for secure random names
- Configure file permissions to owner-only using JavaScript mode `0o600` (POSIX `0600`) when creating temporary files
- Use library cleanup callbacks or `tmp.setGracefulCleanup()` to remove files on exit - `tmp.file()` hands its callback `(err, path, fd, cleanupCallback)`, so write through the `fd` and invoke `cleanupCallback()` in a `finally`
- Avoid race conditions by using exclusive file creation flags (`wx` mode)
- Store sensitive temporary data in user-specific directories or system secure temp locations
- Implement error handling to ensure cleanup occurs even when operations fail
