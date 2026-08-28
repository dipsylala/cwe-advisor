# CWE-377: Insecure Temporary File - C#

## LLM Guidance

Insecure temporary file creation occurs when applications create files with predictable names, insecure permissions, or without proper cleanup mechanisms. Create temporary files atomically with unpredictable names, exclusive access, delete-on-close cleanup, and restrictive ACLs.

## Key Principles

- Use an unpredictable filename and create it atomically with `FileMode.CreateNew`
- Enable `FileOptions.DeleteOnClose` to ensure automatic cleanup when file handles close
- Apply restrictive ACLs limiting access to the current user and SYSTEM
- Implement deterministic disposal patterns using `using` statements
- Validate temporary directory paths before creating files
- Prefer `Directory.CreateTempSubdirectory()` (.NET 7+), which creates a private directory atomically - on Unix it is created with `0700`, so files placed inside inherit that protection
- Avoid `Path.GetTempFileName()`: it wraps `GetTempFileNameW`, whose name space is only 65535 values per directory, so it can fail or collide under load and the file is created before you can set an ACL on it
- Pass the mode at creation with `UnixCreateMode` (.NET 8+) on Unix and an ACL at construction on Windows, rather than calling `SetAccessControl()` after the file exists
- `File.WriteAllText()` on a temp path creates or truncates whatever is already there - use `FileMode.CreateNew` so a planted file is refused instead
- Do not derive the name from `new Random()`, which is not a CSPRNG

## Taint Sinks

`Path.GetTempFileName()`, manual `Path.Combine(Path.GetTempPath(), fixedName)`, `File.Create()` with a predictable path

## Remediation Steps

- Replace manual filename construction with `Path.GetRandomFileName()` under `Path.GetTempPath()`, created atomically using `FileMode.CreateNew` and `FileShare.None`
- Add `FileOptions.DeleteOnClose` flag to `FileStream` constructor for automatic deletion
- Configure `FileSecurity` with ACLs restricting access to current user
- Wrap file operations in `using` statements to ensure cleanup on exceptions
- Use `FileOptions.Encrypted` when handling sensitive data in temporary files
- Validate `Path.GetTempPath()` output points to expected secure location
