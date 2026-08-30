# CWE-316: Cleartext Storage of Sensitive Information in Memory - Java

## LLM Guidance

Storing sensitive data (passwords, cryptographic keys, tokens) in memory as cleartext exposes it to heap dumps, debuggers, and memory disclosure vulnerabilities. Java strings are immutable, so their backing character array cannot be proactively zeroed and lingers in heap memory for an indeterminate time until garbage collection reclaims it. Use `char[]` for passwords, clear arrays explicitly with `Arrays.fill()`, and avoid string operations on credentials.

## Key Principles

- Use mutable data structures: Prefer `char[]` or `byte[]` over `String` for sensitive data
- Clear immediately after use: Zero out arrays in `finally` blocks to ensure cleanup
- Minimize lifetime: Process and discard sensitive data as quickly as possible
- Avoid string conversions: Never call `new String(charArray)` or similar on credentials
- Use secure APIs such as `javax.crypto.SecretKey`, `java.security.KeyStore`, and `Destroyable` interfaces
- Take passwords as `char[]` and clear them (`Arrays.fill(password, '\0')`) - `JPasswordField.getPassword()`'s own javadoc recommends this ("it is recommended that the returned character array be cleared after use by setting each character to zero"), while `getText()` has been `@Deprecated` since Java 2 v1.2 specifically "for security reasons" and returns a `String` that cannot be erased
- `BCryptPasswordEncoder.matches()` accepts `CharSequence`, but Spring Security's own implementation calls `.toString()` on it before hashing - wrapping a `char[]` with `CharBuffer.wrap(password)` does not avoid the `String` copy this specific encoder makes, it only avoids creating one at the call site
- `PBEKeySpec` holds its own copy and offers `clearPassword()`; call it, and drop `SecretKeySpec` material as soon as the operation completes
- A `Cleaner` runs after the object is unreachable, so it bounds how long a secret lingers rather than removing it promptly - prefer an explicit clear in a `finally` block

## Taint Sinks

`String password` fields/parameters, `new String(charArray)`, string concatenation of credentials

## Remediation Steps

- Replace `String password` parameters with `char[] password`
- Add `Arrays.fill(password, '\0')` in `finally` blocks after processing
- Remove any `.toString()`, string concatenation, or logging of sensitive values
- Use `Destroyable`, `SecretKey`, `KeyStore`, or clearly documented framework wrappers such as `GuardedString` where available
- Implement `AutoCloseable` or `Destroyable` for credential holder classes
- Review heap dump and debugging configurations to prevent memory exposure
