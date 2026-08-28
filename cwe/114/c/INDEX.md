# CWE-114: Process Control - C

## LLM Guidance

In C, CWE-114 occurs when loading shared libraries (`dlopen()`, `LoadLibrary()`) or executing processes (`exec*()`, `CreateProcess()`) without proper validation. Attackers exploit this through DLL hijacking, LD_PRELOAD attacks, and path manipulation.

**Primary Defence**: Use absolute paths, validate all inputs, disable unsafe search paths, and set secure file permissions.

## Key Principles

- Use absolute paths for all library loads and process executions
- Validate and sanitize all external inputs before use in library/process calls
- Disable current directory library search on Windows (`SetDllDirectory("")`)
- Set restrictive file permissions (755 for executables, owned by trusted user)
- Verify library signatures and integrity before loading
- Resolve the library or executable to an absolute path under a directory the process cannot write to, and check it with `realpath()` before use - a relative name is resolved through a search path the environment controls. Call `realpath(path, NULL)` so the function allocates a correctly sized result; passing your own buffer requires it to be at least `PATH_MAX` bytes, because that is how much `realpath()` may write
- Set `DT_RUNPATH` (rather than the deprecated `DT_RPATH`) at link time so the loader's search order is fixed by the binary, and note `LD_LIBRARY_PATH` still precedes `DT_RUNPATH`, so a set-user-ID binary is what actually ignores it
- Use `execve()` with an explicit environment rather than inheriting one, and check for `ENOENT` rather than assuming the target was found

## Taint Sinks

`dlopen()`, `LoadLibrary()`, `LoadLibraryEx()`, `exec*()` family, `CreateProcess()`, `system()`

## Remediation Steps

- Replace all relative paths with absolute, validated paths
- Implement whitelist validation for library/executable names, rejecting any containing `/` or `..`, and pass `RTLD_NOW | RTLD_LOCAL` to `dlopen()` so the loaded symbols are not exported globally
- Use `secure_getenv()` on Linux or sanitize environment variables
- Call `SetDllDirectory("")` before any `LoadLibrary()` on Windows
- Set `LD_LIBRARY_PATH` restrictions and use RPATH with `$ORIGIN` carefully
- Verify file ownership and permissions before loading
