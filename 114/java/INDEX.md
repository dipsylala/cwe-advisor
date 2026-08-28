# CWE-114: Process Control - Java

## LLM Guidance

In Java, CWE-114 occurs when loading native libraries or executing processes with untrusted input, enabling attackers to inject malicious libraries via DLL hijacking or execute arbitrary commands. The core fix is validating all inputs against strict allowlists and using absolute paths for library loading.

## Key Principles

- Use `System.load()` with absolute paths instead of `System.loadLibrary()` with relative names
- Validate all external inputs against strict allowlists before using in `ProcessBuilder` or library loading
- Set `java.library.path` explicitly and restrict to trusted directories
- Avoid constructing library names or process commands from user input

## Taint Sinks

`System.loadLibrary()`, `System.load()` with unvalidated path, `Runtime.exec()`, `ProcessBuilder` with untrusted args

## Remediation Steps

- Replace `System.loadLibrary(userInput)` with `System.load(ABSOLUTE_TRUSTED_PATH)`
- Validate process commands against allowlist before passing to `ProcessBuilder`
- Use canonical paths with `File.getCanonicalPath()` to prevent path traversal
- Set environment variables explicitly using `ProcessBuilder.environment()` to prevent injection
- Implement input validation that rejects special characters and path separators
