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
- Avoid `Path.GetTempFileName()`: through .NET 7 (and always on .NET Framework), it can fail with `IOException` after 65535 temp files accumulate in the directory - Microsoft states this cap is gone on every OS from .NET 8 onward - but the file is created before you can set an ACL on it regardless of version
- Pass the mode at creation with `FileStreamOptions.UnixCreateMode` (.NET 7+) on Unix and an ACL at construction on Windows, rather than calling `SetAccessControl()` after the file exists - without it, `Path.GetRandomFileName()` plus `FileMode.CreateNew` requests the default 0666 on Unix, which umask typically reduces to 0644 (world-readable), weaker than the `GetTempFileName()` pattern being replaced, which goes through `mkstemps` and lands on 0600
- `File.WriteAllText()` on a temp path creates or truncates whatever is already there - use `FileMode.CreateNew` so a planted file is refused instead
- Do not derive the name from `new Random()`, which is not a CSPRNG

## Taint Sinks

`Path.GetTempFileName()`, manual `Path.Combine(Path.GetTempPath(), fixedName)`, `File.Create()` with a predictable path

## Remediation Steps

- Replace manual filename construction with `Path.GetRandomFileName()` under `Path.GetTempPath()`, created atomically using `FileMode.CreateNew` and `FileShare.None`
- Add `FileOptions.DeleteOnClose` flag to `FileStream` constructor for automatic deletion
- Configure `FileSecurity` with ACLs restricting access to current user
- Wrap file operations in `using` statements to ensure cleanup on exceptions
- `FileOptions.Encrypted` is Windows/NTFS-only defense-in-depth: it throws `UnauthorizedAccessException` on any filesystem that doesn't support it, including every non-Windows platform, so guard its use or encrypt the contents at the application level instead
- Validate `Path.GetTempPath()` output points to expected secure location
