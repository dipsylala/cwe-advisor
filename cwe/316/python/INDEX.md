# CWE-316: Cleartext Storage of Sensitive Information in Memory - Python

## LLM Guidance

Storing sensitive data (passwords, API keys, cryptographic keys) in memory as cleartext in Python exposes it to memory dumps, debuggers, and memory disclosure vulnerabilities. Python strings and many library APIs create immutable copies, so Python cannot reliably guarantee complete memory clearing. Minimize lifetime and copies, use mutable buffers when downstream APIs accept them, and explicitly zero those buffers after use.

## Key Principles

- Use mutable types (`bytearray`) instead of immutable strings where the receiving API accepts mutable buffers
- Minimize the lifetime of secrets in memory-clear immediately after use
- Avoid operations that create copies of sensitive data (string concatenation, logging)
- Use secure input methods (`getpass`) and avoid printing/logging credentials
- Consider memory-locking libraries (`mlock`) for highly sensitive applications
- A `str` cannot be wiped: convert to a `bytearray` at the boundary and clear it with a slice assignment, since `bytes(password)` produces an immutable copy that stays until collected
- Compare secrets with `hmac.compare_digest()`, which is constant-time as well as exact
- Where the platform allows it, keep the secret out of a normal file entirely (`memfd_create`, an anonymous mapping) rather than writing it and deleting it afterwards

## Taint Sinks

`str` variables/attributes holding passwords or keys, f-string/`+` concatenation of credentials, `input()` for passwords

## Remediation Steps

- Replace string-based credentials with `bytearray` for passwords and keys, and hand them to downstream APIs as a `memoryview` so no extra copy is made
- Implement explicit byte-by-byte zeroing before deallocation
- Use context managers or try-finally blocks to ensure cleanup occurs
- Avoid storing secrets in exception messages or stack traces
- Use `getpass.getpass()` instead of `input()`, but account for the temporary immutable string it returns
- Integrate libraries like `ctypes` with `mlock()` for critical data protection
