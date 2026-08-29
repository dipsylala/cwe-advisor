# CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)

## LLM Guidance

Weak PRNG vulnerabilities occur when applications use cryptographically insecure, general-purpose random number generators for security-sensitive operations such as session tokens, cryptographic keys, or nonces. Attackers can predict or reproduce these values, compromising security. Fix: Replace weak PRNGs with cryptographically secure alternatives.

## Key Principles

- Always use cryptographically secure PRNGs for security-sensitive randomness
- Never use standard, general-purpose PRNGs for tokens, keys, salts, or nonces
- Never implement custom random number generators
- Avoid predictable seeding patterns (time-based, PID-based, static seeds)
- Decide first whether the value is security-relevant: shuffling a carousel, retry jitter, an A/B bucket, or a cache-busting suffix is usually not a finding, and closing it with that reason recorded is a legitimate outcome
- Treat as a finding even when it does not look like one: session and remember-me identifiers, password-reset and verification tokens, CSRF tokens, API keys, OTP codes, coupon codes with monetary value, "unguessable" share URLs, and every salt, IV, nonce and key
- Three things move a borderline case toward finding: the value is observable by someone not entitled to what it protects, guessing it grants access rather than revealing information, and it is long-lived enough for repeated attempts
- Ask what a *duplicate* would cost separately from what a guess would cost: a GCM nonce needs uniqueness more urgently than unpredictability, and a deterministic generator restarted from the same seed - two replicas launched together, a container restored from a checkpoint - repeats its whole sequence
- The dangerous names are rarely the obvious ones: grep for the uses (token, secret, nonce, salt, code, key) as well as for generators, since `str_shuffle()`, `array_rand()`, `RandomStringUtils.randomAlphanumeric()`, `ThreadLocalRandom.current()`, `Random.Shared`, `uniqid()` and `math/rand/v2` all pass a search for `rand(`

## Remediation Steps

- Identify weak PRNG usage - Review flaw details for file/line number and trace data flow to determine if random values are used for security purposes (see the language-specific guidance's Taint Sinks for concrete function names)
- Replace with secure alternatives - swap in the language's cryptographically secure random generator (see the language-specific guidance's Remediation Steps)
- Verify proper initialization - Ensure secure PRNGs are properly seeded by the OS
- Review all usages - Search codebase for other instances of weak PRNGs in security contexts
- Test the fix - Verify random values are unpredictable and non-reproducible across sessions
