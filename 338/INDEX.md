# CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)

## LLM Guidance

Weak PRNG vulnerabilities occur when applications use cryptographically insecure, general-purpose random number generators for security-sensitive operations such as session tokens, cryptographic keys, or nonces. Attackers can predict or reproduce these values, compromising security. Fix: Replace weak PRNGs with cryptographically secure alternatives.

## Key Principles

- Always use cryptographically secure PRNGs for security-sensitive randomness
- Never use standard, general-purpose PRNGs for tokens, keys, salts, or nonces
- Never implement custom random number generators
- Avoid predictable seeding patterns (time-based, PID-based, static seeds)

## Remediation Steps

- Identify weak PRNG usage - Review flaw details for file/line number and trace data flow to determine if random values are used for security purposes (see the language-specific guidance's Taint Sinks for concrete function names)
- Replace with secure alternatives - swap in the language's cryptographically secure random generator (see the language-specific guidance's Safe Pattern)
- Verify proper initialization - Ensure secure PRNGs are properly seeded by the OS
- Review all usages - Search codebase for other instances of weak PRNGs in security contexts
- Test the fix - Verify random values are unpredictable and non-reproducible across sessions
