# CWE-252: Unchecked Return Value

## LLM Guidance

Unchecked return values occur when code ignores error indicators from security-critical functions (setuid, chroot, malloc, read, write), assuming operations succeeded when they may have failed. This leads to continued execution with wrong privileges, uninitialized memory, or invalid state. Always check return values and handle failures securely.

## Key Principles

- Check all return values from security-critical functions (privilege changes, memory allocation, file I/O, cryptographic operations)
- Fail securely when operations don't succeed-terminate, log errors, or revert to safe state
- Never assume success for functions that can fail (setuid, malloc, chroot, read/write)
- Validate both return codes and side effects (e.g., verify privileges actually changed)
- Use compiler warnings and static analysis to detect unchecked returns
- Logging the failure and continuing is functionally the same as not checking: the branch needs a `return`, an `abort`, or a thrown error after it
- Check how much was done, not only that it did not error: a read that returns fewer bytes than requested is a short read, and treating it as complete truncates or corrupts the data silently
- After a privilege-drop call returns success, re-query the actual privilege level - a partial drop that leaves a saved or effective identity unchanged still reports success
- A "safe" wrapper whose own failure path only logs or returns a sentinel moves the bug one layer down unless every caller checks the wrapper's result
- Route the neighbours correctly: an unchecked privilege-drop specifically is CWE-273, an unchecked result that is later dereferenced becomes CWE-476, an error that *is* detected but not acted on is CWE-390, and a tool still reporting CWE-391 for this shape is using a number MITRE is retiring

## Remediation Steps

- Locate unchecked calls - Find setuid/setgid, malloc/calloc, file operations (open/read/write), chroot/chdir, and crypto functions without return value checks
- Add explicit checks - Wrap critical calls with `if (func() != 0)` or `if (ptr == NULL)` checks
- Handle failures securely - Log the error, clean up resources, and terminate or return error codes-never continue with invalid state
- Verify side effects - After privilege changes, confirm actual UID/GID with getuid/getgid
- Use defensive patterns - Initialize pointers to NULL, check errno after failures, validate file descriptors before use
- Enable compiler warnings - Use `-Wall -Wextra` (GCC/Clang) or `/W4` (MSVC) and treat unused return value warnings as errors
