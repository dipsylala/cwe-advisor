# CWE-316: Cleartext Storage of Sensitive Information in Memory - Python

## LLM Guidance

Storing sensitive data (passwords, API keys, cryptographic keys) in memory as cleartext in Python exposes it to memory dumps, debuggers, and memory disclosure vulnerabilities. Python strings and many library APIs create immutable copies, so Python cannot reliably guarantee complete memory clearing. Minimize lifetime and copies, use mutable buffers when downstream APIs accept them, and explicitly zero those buffers after use.

## Key Principles

- Use mutable types (`bytearray`) instead of immutable strings where the receiving API accepts mutable buffers
- Minimize the lifetime of secrets in memory-clear immediately after use
- Avoid operations that create copies of sensitive data (string concatenation, logging)
- Use secure input methods (`getpass`) and avoid printing/logging credentials
- Consider memory-locking libraries (`mlock`) for highly sensitive applications

## Remediation Steps

- Replace string-based credentials with `bytearray` for passwords and keys
- Implement explicit byte-by-byte zeroing before deallocation
- Use context managers or try-finally blocks to ensure cleanup occurs
- Avoid storing secrets in exception messages or stack traces
- Use `getpass.getpass()` instead of `input()`, but account for the temporary immutable string it returns
- Integrate libraries like `ctypes` with `mlock()` for critical data protection

## Safe Pattern

```python
import getpass

def authenticate():
    password = bytearray(getpass.getpass("Password: "), 'utf-8')
    try:
        # Prefer APIs that accept a mutable buffer or memoryview to avoid extra copies.
        result = verify_credentials(memoryview(password))
        return result
    finally:
        # Clear sensitive data
        for i in range(len(password)):
            password[i] = 0
        del password
```
