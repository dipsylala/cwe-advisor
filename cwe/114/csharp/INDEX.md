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
- `PermissionSet`-based sandboxing via `AppDomain.CreateDomain(string, Evidence, AppDomainSetup,
  PermissionSet, StrongName[])` is a .NET Framework-only API - that overload does not exist on .NET
  Core/.NET 5+ at all, so a ported codebase fails to compile rather than silently losing the sandbox.
  The parameterless `CreateDomain(string)` overload does exist on both, but is obsolete
  (`SYSLIB0024`) and throws `PlatformNotSupportedException` at runtime on .NET Core/.NET 5+ - either
  way, no app-domain sandbox is available; isolate in a separate process instead
- Use `ProcessStartInfo.ArgumentList` rather than `Arguments` so each argument is escaped
  individually, and never launch through `cmd.exe`, whose parsing reintroduces shell semantics.
  `ArgumentList` exists only on .NET Core 2.1, .NET Standard 2.1 and later - it is absent from every
  .NET Framework version, so on Framework the escaping has to be done by hand around `Arguments`

## Taint Sinks

`Process.Start()`, `[DllImport]` with unvalidated path, `LoadLibrary()`/`LoadLibraryEx()` via P/Invoke

## Remediation Steps

- Call `SetDllDirectory("")` at application startup to remove the current directory from the DLL
  search order. Two limits belong in the fix: the directories listed in `PATH` are still searched
  afterwards, so this narrows hijacking rather than closing it, and for an unpackaged Win32 process
  the setting is inherited by child processes started from it
- Use `LoadLibraryEx` with `LOAD_LIBRARY_SEARCH_SYSTEM32` flag for system DLLs
- Validate DLL/executable paths against allowlist before P/Invoke or Process.Start()
- Use ProcessStartInfo with `UseShellExecute = false` and escape arguments properly
- Do not treat strong-naming as a load-integrity control. Microsoft's guidance is explicit that
  strong names provide a unique identity only, and that on .NET Core and .NET 5+ the runtime never
  validates the strong-name signature nor uses it for binding - so the check a remediation would be
  relying on does not run. Where an assembly's origin must be established, Authenticode-sign it and
  verify the publisher, and load only from directories the application controls
- Implement file integrity checks (digital signatures) before loading external DLLs
