# CWE-377: Insecure Temporary File - C\#

## LLM Guidance

Insecure temporary file creation occurs when applications create files with predictable names, insecure permissions, or without proper cleanup mechanisms. Create temporary files atomically with unpredictable names, exclusive access, delete-on-close cleanup, and restrictive ACLs.

## Key Principles

- Use an unpredictable filename and create it atomically with `FileMode.CreateNew`
- Enable `FileOptions.DeleteOnClose` to ensure automatic cleanup when file handles close
- Apply restrictive ACLs limiting access to the current user and SYSTEM
- Implement deterministic disposal patterns using `using` statements
- Validate temporary directory paths before creating files

## Remediation Steps

- Replace manual filename construction with an unpredictable name created atomically using `FileMode.CreateNew`
- Add `FileOptions.DeleteOnClose` flag to `FileStream` constructor for automatic deletion
- Configure `FileSecurity` with ACLs restricting access to current user
- Wrap file operations in `using` statements to ensure cleanup on exceptions
- Use `FileOptions.Encrypted` when handling sensitive data in temporary files
- Validate `Path.GetTempPath()` output points to expected secure location

## Safe Pattern

```csharp
string tempFile = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
using FileStream fs = new FileStream(
    tempFile,
    FileMode.CreateNew,
    FileAccess.ReadWrite,
    FileShare.None,
    4096,
    FileOptions.DeleteOnClose);

byte[] data = GetDataToWrite();
fs.Write(data, 0, data.Length);
```
