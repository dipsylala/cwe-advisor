# CWE-597: Use of Wrong Operator in String Comparison - C\#

## LLM Guidance

Using reference equality on object-typed values instead of value equality can compare object identity rather than content, causing security checks to fail unpredictably and enabling authentication bypass and logic errors. C# string operands use value equality with `==`, but security-critical comparisons should still use `String.Equals()` with an explicit `StringComparison` parameter for clarity and null handling.

## Key Principles

- Use `.Equals()` or `String.Equals()` with explicit comparison mode for security-sensitive string comparisons
- Specify `StringComparison.Ordinal` for case-sensitive or `StringComparison.OrdinalIgnoreCase` for case-insensitive comparisons
- Avoid culture-sensitive comparisons (`CurrentCulture`) in authentication, authorization, and security checks
- Never rely on string interning for security decisions

## Remediation Steps

- Identify string comparisons in security-sensitive code paths, especially where values are typed as `object` or comparison mode is implicit
- Replace with `.Equals()` method calls with explicit `StringComparison` parameter
- For null-safe comparisons, use `String.Equals(str1, str2, StringComparison.Ordinal)`
- Review authentication, authorization, token validation, and input validation logic
- Add unit tests covering non-interned strings to verify correct comparison behavior
- Use static analysis tools to flag `==` usage on string types

## Safe Pattern

```csharp
// RISKY: implicit comparison mode and null handling
if (userRole == "Admin") { /* grant access */ }

// SAFE: Value comparison with explicit mode
if (userRole.Equals("Admin", StringComparison.Ordinal)) { /* grant access */ }

// SAFE: Null-safe static method
if (String.Equals(userRole, "Admin", StringComparison.Ordinal)) { /* grant access */ }

// SAFE: Case-insensitive when appropriate
if (fileExtension.Equals(".exe", StringComparison.OrdinalIgnoreCase)) { /* block */ }
```
