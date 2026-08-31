# CWE-114: Process Control - Java

## LLM Guidance

In Java, CWE-114 occurs when loading native libraries or executing processes with untrusted input, enabling attackers to inject malicious libraries via DLL hijacking or execute arbitrary commands. The core fix is validating all inputs against strict allowlists and using absolute paths for library loading.

## Key Principles

- Use `System.load()`, which takes a full absolute path, instead of `System.loadLibrary()` - the latter takes a bare library name with no path component at all (the javadoc forbids any prefix, extension, or path in it) and resolves it by searching `java.library.path`, so an attacker who can influence that search path controls what actually loads even though the caller's own string looks fixed
- Validate all external inputs against strict allowlists before using in `ProcessBuilder` or library loading
- Set `java.library.path` explicitly and restrict to trusted directories
- Avoid constructing library names or process commands from user input
- `Runtime.exec(String)` does not invoke a shell - it tokenizes the string on whitespace only (no quote or metacharacter handling) and execs the first token directly, so `;`/`|` are inert unless the command itself names a shell. The real risk with a single command string is argument-count and tokenization confusion, not shell injection; it's also `@Deprecated(since="18")` specifically because of this trap - treat its presence as a migration signal
- An argument array passed to `ProcessBuilder` closes shell-metacharacter injection but not argument injection: a value beginning with `-` can still be read as a flag by the target program (`tar --to-command`, `ssh -o ProxyCommand=`) - pass `--` before user-supplied operands where the program supports it, or resolve the value against a fixed base so it can't start with `-`
- `ProcessBuilder.environment().clear()` leaves the child with no `PATH`/`HOME`/`TMPDIR` and breaks most real executables - replace the environment with an explicit, complete set of variables rather than emptying it

## Taint Sinks

`System.loadLibrary()`, `System.load()` with unvalidated path, `Runtime.exec()`, `ProcessBuilder` with untrusted args

## Remediation Steps

- Replace `System.loadLibrary(userInput)` with `System.load(ABSOLUTE_TRUSTED_PATH)`
- Validate process commands against allowlist before passing to `ProcessBuilder`
- Set environment variables explicitly using `ProcessBuilder.environment()` to prevent injection
- Implement input validation that rejects special characters and path separators
