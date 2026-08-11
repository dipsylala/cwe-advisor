# CWE-330: Use of Insufficiently Random Values

## LLM Guidance

Insufficient randomness occurs when applications use predictable or weak random number generators (PRNGs) for security-sensitive operations like session tokens, passwords, or cryptographic keys. Attackers can predict or brute-force these values, compromising authentication, encryption, and other security controls. Security tokens and secrets must use cryptographically secure random number generators (CSPRNGs), never predictable values.

## Key Principles

- Use CSPRNGs for all security operations - Session IDs, tokens, passwords, keys, salts, and nonces require cryptographic-grade randomness
- Never use standard, general-purpose random functions - they are predictable and unsuitable for security
- Avoid predictable seeds - Time-based or sequential seeds enable attackers to reproduce random sequences
- Ensure sufficient entropy - Generate values with adequate length and randomness for the security context
- Review all random value usage - Audit both direct generation and third-party library calls

## Remediation Steps

- Identify weak generators - Locate uses of general-purpose random functions or predictable seeding in security contexts (see the language-specific guidance's Taint Sinks for concrete function names)
- Replace with secure APIs - swap in the language or platform's cryptographically secure random generator (see the language-specific guidance's Safe Pattern)
- Trace data flow - Determine what each random value protects (tokens, keys, IDs) and validate appropriate strength
- Use framework helpers - Prefer built-in secure token generators from frameworks (e.g., Django's `get_random_string`, Spring Security's token generators)
- Validate entropy sources - Ensure the CSPRNG has access to quality system entropy
- Test unpredictability - Verify generated values are non-sequential and cannot be predicted from previous outputs
