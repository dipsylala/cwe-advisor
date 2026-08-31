# CWE-114: Process Control - C

## LLM Guidance

In C, CWE-114 occurs when loading shared libraries (`dlopen()`, `LoadLibrary()`) or executing processes (`exec*()`, `CreateProcess()`) without proper validation. Attackers exploit this through DLL hijacking, LD_PRELOAD attacks, and path manipulation.

**Primary Defence**: Use absolute paths, validate all inputs, disable unsafe search paths, and set secure file permissions.

## Key Principles

- Use absolute paths for all library loads and process executions
- Validate and sanitize all external inputs before use in library/process calls
- Disable current directory library search on Windows (`SetDllDirectory("")`), or prefer `LoadLibraryEx()` with `LOAD_LIBRARY_SEARCH_SYSTEM32`/`LOAD_LIBRARY_SEARCH_APPLICATION_DIR` flags, a stronger and more current mitigation - the commonly-assumed risk (current working directory) is already lower priority than the System32/Windows directories under `SafeDllSearchMode` (default since XP SP2); the application's own directory searches first and is often user-writable
- Set restrictive file permissions (755 for executables, owned by trusted user)
- Verify library signatures and integrity before loading - hash from an already-open file descriptor and load through that same descriptor (`/proc/self/fd/<n>` on Linux, `fdlopen()` on FreeBSD), not by path a second time; verifying a path then reopening it for `dlopen()` leaves a window where a writable library directory can swap the file in between
- Resolve the library or executable to an absolute path under a directory the process cannot write to, and check it with `realpath()` before use - a relative name is resolved through a search path the environment controls. Call `realpath(path, NULL)` so the function allocates a correctly sized result; passing your own buffer requires it to be at least `PATH_MAX` bytes, because that is how much `realpath()` may write. `realpath()` fails with `ENOENT` on a path that doesn't exist yet, so for an *output* path, canonicalize the containing directory instead of the full path. When comparing a canonicalized path against a base directory for containment, include the trailing separator in the comparison - a bare prefix match lets a sibling like `/opt/app/lib-backup` pass a check meant to scope `/opt/app/lib`
- `system()` has no safe form regardless of input - it always spawns `/bin/sh -c` (or `cmd.exe /c` on Windows) on the given string. Replace it with `posix_spawn()` or `fork()`+`execve()` rather than trying to sanitize the string first
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
