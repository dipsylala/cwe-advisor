# CWE-316: Cleartext Storage of Sensitive Information in Memory

## LLM Guidance

Storing sensitive data (passwords, keys, tokens, PII) in memory as cleartext exposes it to memory dumps, swap files, debuggers, and memory disclosure vulnerabilities. The core fix is to minimize the lifetime of sensitive data in memory, clear it immediately after use, and prevent it from being written to disk.

## Key Principles

- Avoid storing sensitive data in cleartext memory whenever possible
- Minimize the lifetime and exposure of sensitive data in memory
- Explicitly zero/overwrite memory containing secrets after use
- Use secure memory types and APIs designed for sensitive data
- Prevent sensitive data from being swapped to disk or captured in dumps
- Be honest about what clearing buys: a moving collector (JVM, CLR, V8) relocates live objects, so one logical secret exists at addresses the program never held a reference to, and zeroing the array you can reach does nothing about those
- The wipe covers only the buffer it is given - every conversion on the way to the consuming API (to a `String`, a JSON body, a log record) makes a copy it cannot reach
- In C and C++ a plain `memset` over a buffer the compiler can see is dead is removable under the as-if rule; use `explicit_bzero()` or `memset_s()`
- `SecureString` is not the answer on .NET: Microsoft recommends against it for new development generally, not only off Windows, because every use has to convert back to plain text
- Prefer a vault, HSM, cloud KMS, or a short-lived token over an application-managed plaintext key, so the secret's residency in process memory is bounded by design rather than by cleanup code

## Remediation Steps

- Identify where sensitive data enters memory - locate files, line numbers, and code patterns storing passwords, keys, tokens, or PII
- Zero memory immediately after use - overwrite arrays/buffers with zeros using the language or platform's secure-clear function (see the language-specific guidance's Remediation Steps for concrete APIs)
- Use mutable buffers over immutable strings where possible, or platform-specific secure memory APIs
- Minimize data lifetime - load sensitive data only when needed, clear it in finally blocks or defer statements
- Prevent swapping - use the platform's memory-locking API for highly sensitive data
- Avoid logging or serializing variables containing secrets
