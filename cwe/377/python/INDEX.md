# CWE-377: Insecure Temporary File - Python

## LLM Guidance

Insecure temporary file creation occurs when applications create files with predictable names, insecure permissions, or in shared directories without proper protection. Python's `tempfile` module provides secure alternatives that generate unpredictable names with restricted permissions and automatic cleanup. Always use `tempfile.NamedTemporaryFile()` or `tempfile.mkstemp()` instead of manually creating files in `/tmp` or similar directories.

## Key Principles

- Use Python's `tempfile` module exclusively for temporary file operations
- Never hardcode temporary file names or use predictable patterns
- Ensure file permissions are restrictive (mode 0o600) to prevent unauthorized access
- Implement automatic cleanup using context managers or `delete=True` parameter
- Avoid creating temporary files in world-writable directories like `/tmp` without proper protections
- `tempfile.mkdtemp()` creates a private directory atomically, so files created inside it inherit its protection - the stronger option when several temp files are involved
- Where a raw descriptor is needed, `os.open(path, os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)` is the safe primitive: `O_EXCL` refuses an existing name, `O_NOFOLLOW` refuses a planted symlink, and the mode is applied at creation
- `os.path.exists()` followed by `open()` is the race this weakness is about; `os.makedirs(..., exist_ok=True)` on a shared path has the same problem, since the directory may already exist and belong to someone else
- `tempfile` names come from `random.Random`, not from a CSPRNG - they are hard to guess and are not a secret
- On Windows, `os.unlink()` on a path with an open file handle raises `PermissionError: [WinError 32]`; close the handle before removing the path in a `finally` block, or use `delete=True`/a context manager instead

## Taint Sinks

`open('/tmp/...')` with a predictable name, `tempfile.mktemp()` (deprecated, insecure), manual `open(f"/tmp/{name}")`

## Remediation Steps

- Replace manual file creation with `tempfile.NamedTemporaryFile()` or `tempfile.mkstemp()`, wrapping the raw descriptor `mkstemp()` returns with `os.fdopen()` and removing the path with `os.unlink()` in a `finally`
- Use context managers (`with` statements) to ensure automatic cleanup
- Set `delete=True` for auto-removal or explicitly handle cleanup in exception handlers
- Verify file permissions are restrictive (default 0o600 is secure)
- For temporary directories, use `tempfile.TemporaryDirectory()` with context managers
- Avoid passing temporary file paths to untrusted code or processes
