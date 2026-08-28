# CWE-597: Use of Wrong Operator in String Comparison - Java

## LLM Guidance

Using reference equality (`==`) instead of value equality (`.equals()`) for string comparison in Java compares memory addresses, not content, causing security checks to fail unpredictably when strings are dynamically created vs literals, enabling authentication bypass and logic errors.

**Primary Defence:** Always use `.equals()` for string content comparison; use constant-first pattern for null safety.

## Key Principles

- Replace `==` with `.equals()` for all string content comparisons
- Use `"expected".equals(variable)` pattern to prevent NullPointerException
- Use `Objects.equals(a, b)` when both strings may be null
- Consider `equalsIgnoreCase()` for case-insensitive comparisons
- Never use `==` except for explicit null checks
- `toLowerCase()`/`toUpperCase()` without a `Locale` argument use the default locale, so normalizing before a comparison can change the result depending on where the JVM runs - pass `Locale.ROOT`
- Use `MessageDigest.isEqual()` for a digest, MAC, or token comparison, which is constant-time as well as value-based

## Taint Sinks

`==`, `!=` on `String` objects in authentication, authorization, or token-validation logic

## Remediation Steps

- Scan codebase for `string1 == string2` patterns in conditionals and authentication logic
- Replace with `.equals()`, putting known constant first where possible
- Add null checks or use `Objects.equals()` where both values may be null
- Prioritize authentication, authorization, and security-critical paths first; a stored password hash is verified with `passwordEncoder.matches(raw, storedHash)`, never with `.equals()`
- Run comprehensive test suite to verify logic correctness after changes
- Enable static analysis rules (e.g., PMD, SpotBugs) to prevent future violations
