# CWE-114: Process Control - C#

## LLM Guidance

In C#, CWE-114 vulnerabilities occur when loading DLLs or executing processes without proper validation. Attackers exploit weak library loading through DLL hijacking, DllImport path manipulation, and Process.Start() command injection. .NET applications are vulnerable to both native DLL loading (P/Invoke) and managed assembly loading.

**Primary Defence:** Use `SetDllDirectory()` and `LoadLibraryEx` with `LOAD_LIBRARY_SEARCH_SYSTEM32` flag, validate all paths against allowlists, disable current directory DLL search, and use full absolute paths for Process.Start().

## Key Principles

- Restrict DLL search paths using `SetDllDirectory("")` to remove current directory from search order
- Validate all file paths against strict allowlists before loading assemblies or executing processes
- Use absolute paths with known-safe directories (e.g., System32, application directory)
- Apply least privilege principles when spawning child processes
- Never concatenate user input directly into process arguments or DLL paths
- `Assembly.LoadFrom()` with a path from configuration or a request loads and runs whatever is there - resolve to an absolute path under a directory the application account cannot write to, and verify the file's signature (`WinVerifyTrust`, or an Authenticode check) before loading
- `AppDomain.CreateDomain()` and `PermissionSet`-based sandboxing are .NET Framework only and do not exist on .NET Core or later - do not treat a code-access-security boundary as available on a modern runtime; isolate in a separate process instead
- Use `ProcessStartInfo.ArgumentList` rather than `Arguments`, and never launch through `cmd.exe`, whose parsing reintroduces shell semantics

## Taint Sinks

`Process.Start()`, `[DllImport]` with unvalidated path, `LoadLibrary()`/`LoadLibraryEx()` via P/Invoke

## Remediation Steps

- Call `SetDllDirectory("")` at application startup to disable current directory DLL loading
- Use `LoadLibraryEx` with `LOAD_LIBRARY_SEARCH_SYSTEM32` flag for system DLLs
- Validate DLL/executable paths against allowlist before P/Invoke or Process.Start()
- Use ProcessStartInfo with `UseShellExecute = false` and escape arguments properly
- Sign assemblies and enable strong name verification for managed code
- Implement file integrity checks (digital signatures) before loading external DLLs
