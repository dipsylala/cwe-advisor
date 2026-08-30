# CWE-316: Cleartext Storage of Sensitive Information in Memory - JavaScript

## LLM Guidance

Storing sensitive data (passwords, cryptographic keys, tokens) in memory as cleartext in JavaScript exposes it to memory dumps, debugging tools, and memory disclosure vulnerabilities. JavaScript strings are immutable, so nothing in the language lets you proactively zero one - the problem is not that a string "persists" longer than any other garbage-collected value, only that you cannot overwrite it before it becomes unreachable. Use `Buffer` for sensitive data, clear buffers explicitly with `fill(0)`, and avoid logging or concatenating sensitive values.

## Key Principles

- Use mutable Buffers: Store credentials in `Buffer` objects instead of strings
- Explicit zeroing: Clear sensitive buffers with `.fill(0)` immediately after use
- V8's garbage collector copies live objects during a compacting/scavenging collection, the same way this repo's root CWE-316 guidance describes for other moving collectors - a `Buffer` you zeroed can still have a stale pre-collection copy elsewhere in the heap until that copy is itself collected
- Minimal lifetime: Keep sensitive data in memory only as long as necessary
- Avoid string operations: Never convert sensitive buffers to strings or log them
- Secure comparison: Use `crypto.timingSafeEqual()` for comparing sensitive values

## Taint Sinks

`string` variables holding passwords/keys/tokens, `JSON.stringify()` of credential objects

## Remediation Steps

- Replace string variables holding passwords/keys with `Buffer.from()` or `Buffer.alloc()`
- Wrap sensitive operations in `try-finally` blocks with `.fill(0)` in finally
- Pass buffers directly to crypto functions without converting to strings
- Remove debug logging, console output, and error messages containing sensitive data
- Clear buffers before returning from functions handling credentials
- `libsodium-wrappers` does not protect memory automatically - it exposes `sodium.memzero()`, which still has to be called explicitly on a `Uint8Array`, and its WASM sandbox has no access to the OS-level `mlock`/guard-page protections native libsodium relies on, so treat it as a manual-zeroing helper, not a memory-safety guarantee
