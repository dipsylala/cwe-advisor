# CWE-377: Insecure Temporary File - Java

## LLM Guidance

Insecure temporary file creation occurs when applications create files with predictable names, weak permissions, or in shared directories without proper safeguards, enabling symlink attacks and data tampering. Always use `Files.createTempFile()` with restrictive permissions and ensure proper cleanup.

## Key Principles

- Use `Files.createTempFile()` or `File.createTempFile()` instead of manual path construction
- Set permissions to owner-only (600) using `PosixFilePermissions` before writing sensitive data
- Ensure deterministic cleanup with try-finally blocks or try-with-resources
- Never create temp files with predictable or hardcoded names
- `Files.createTempDirectory()` with `PosixFilePermissions` applied through the creation attributes is the stronger primitive: files placed inside inherit the directory's protection and the mode is set atomically rather than after the fact
- Pass the permissions as a `FileAttribute` at creation - `Files.setPosixFilePermissions()` afterwards leaves a window at the umask default, and it throws `UnsupportedOperationException` on Windows, so guard it by filesystem rather than assuming POSIX
- `deleteOnExit()` registers cleanup for normal JVM shutdown only and leaks the registration for a long-lived process; prefer a try-with-resources wrapper or an `AutoCloseable` holder that deletes deterministically
- OpenJDK's temp names come from `SecureRandom`, but the javadoc does not promise it - treat the name as hard to guess rather than as a secret

## Taint Sinks

`new File(predictablePath)`, `File.createTempFile()` without POSIX permissions set, `FileWriter` writing to a fixed `/tmp` path

## Remediation Steps

- Replace manual file creation with `Files.createTempFile("prefix-", ".tmp")`
- Apply `PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------"))` as the creation attribute for owner-only access
- Wrap operations in try-finally to guarantee deletion via `Files.deleteIfExists()`
- Validate temp directory permissions before use
- Consider in-memory alternatives for highly sensitive data
