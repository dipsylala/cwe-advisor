# CWE-676: Use of Potentially Dangerous Function - C

## LLM Guidance

C's standard library includes functions that are dangerous by convention, not by defect: `strcpy()`, `strcat()`, `gets()`, and `sprintf()` take no destination-size argument, so any caller that skips a manual bounds check can overflow the buffer. `system()` and `popen()` pass their argument to a shell, so untrusted text reaching them enables command injection. The primary remediation is replacing each dangerous function with its bounds-checked equivalent and, for process execution, avoiding the shell entirely.

## Key Principles

- Replace unbounded string functions with bounded equivalents: `strcpy` -> `strlcpy` (BSD, macOS, glibc 2.38+) or `strncpy` with explicit null termination, `strcat` -> `strlcat` or bounded `snprintf`, `sprintf` -> `snprintf`, `gets` -> `fgets`
- Never build a shell command string from untrusted input and pass it to `system()` or `popen()`
- Replace `system()`/`popen()` with `fork()`/`execve()` (or `posix_spawn()`), passing arguments as an array so no shell parses metacharacters
- Terminate `strncpy()` output explicitly - it does not null-terminate whenever the source is as long as or longer than the destination, not only at the exact boundary
- An argument-array `execve` call closes shell metacharacter injection but not option injection: a value starting with `-` can still be read as a flag by the target program itself (`-r`, `--target-directory=...`) - pass `--` before the first attacker-influenced argument where the program supports it, and validate values that could start with `-` regardless
- Where a dangerous function must remain, document why the call site is safe (fixed, non-attacker-controlled input) and add a length or bounds check
- Enforce the ban with static analysis (`cppcheck`, Clang static analyzer) in CI - `-Wformat-security` does not apply here, it only flags a non-literal `printf`/`scanf` format with no arguments (a CWE-134 concern), not `strcpy`/`strcat`/`gets`/`system`/`popen` misuse
- `execvp()`/`execlp()` resolve the program through `PATH`, so a call that looks bounded still runs whatever an attacker-writable path element supplies - use `execve()` with an absolute path and an explicit environment

## Taint Sinks

`strcpy()`, `strcat()`, `gets()`, `sprintf()`, `system()`, `popen()`

## Remediation Steps

- Locate - Search for `strcpy(`, `strcat(`, `gets(`, `sprintf(`, `system(`, `popen(` across the codebase
- Trace data flow - Determine whether the destination buffer size or the command string includes any network, file, or CLI-derived input
- Replace the unsafe pattern - Convert string copies to `strlcpy`/`strncpy`+null-terminate and formatting to `snprintf`; convert shell execution to `execve`-family calls with an argument array
- Bind, encode, validate, or authorize - Pass the destination buffer's actual capacity (via `sizeof` on a fixed array, never a pointer) to every bounded function call
- Break taint after allowlist validation - If a filename or argument must be validated first, assign the validated value to a fresh variable and pass only that to `execve`/`snprintf`
- Harden configuration - Enable `-D_FORTIFY_SOURCE=3` (GCC 12+ with glibc 2.35+, or Clang 9+ with glibc 2.33+; fall back to `=2` on older toolchains) and `-fstack-protector-strong` at compile time as defence-in-depth
- Test - Compile with AddressSanitizer and fuzz string-handling call sites with inputs at and beyond the destination capacity; test replaced shell calls with metacharacters (`; | & $() \``) to confirm they no longer trigger - a metacharacter-only test suite reports the fix complete while option injection through a leading `-` is still open, so test that path too
