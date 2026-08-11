# CWE-597: Use of Wrong Operator in String Comparison

## LLM Guidance

In languages where the default equality operator compares object identity/reference rather than string content, using it for a security-relevant string comparison can pass or fail unpredictably depending on how the strings were constructed (literal vs. dynamically built), enabling authentication bypass and logic errors. The core fix is to always use the language's explicit value/content-equality method for string comparison, never a bare identity operator, in security-critical code - and to confirm which semantics the language actually uses before assuming an operator is safe.

## Key Principles

- Use the language's value/content-equality method for string comparison, never a bare identity operator, in security-critical code
- Apply a constant-first comparison pattern where useful to avoid null-reference errors
- Use constant-time comparison functions for sensitive data (passwords, tokens, secrets) to also avoid timing side-channels
- Confirm which comparison semantics the language actually uses for strings before assuming an operator is safe - see the language-specific guidance
- Prioritize security-critical code: authentication, authorization, token validation

## Remediation Steps

- Search the codebase for identity/reference-based string comparisons in security-critical code paths (see the language-specific guidance's Taint Sinks for the exact operator/pattern to search for)
- Identify security-critical comparisons - passwords, roles, tokens, API keys, session IDs
- Replace identity comparisons with the language's value-equality method
- For secrets, use a constant-time comparison function or library instead of a general-purpose equality check
- Add null-safety handling appropriate to the language
- Verify fixes with unit tests covering both matching and non-matching string scenarios, including dynamically constructed strings
