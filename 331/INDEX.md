# CWE-331: Insufficient Entropy

## LLM Guidance

Insufficient entropy occurs when cryptographic operations (key generation, IV/nonce creation, token generation) use weak randomness sources (time, PID, Math.random) instead of cryptographically secure random number generators, making outputs predictable and enabling cryptographic attacks.

## Key Principles

- Use OS-provided cryptographically secure random number generators (CSPRNGs) for all security-sensitive randomness
- Never use weak entropy sources like timestamps, PIDs, or language-default random functions for cryptographic purposes
- Ensure sufficient entropy length - 128+ bits for session tokens, 256+ bits for encryption keys
- Verify proper seeding of random number generators from OS entropy pools
- Validate that random values cannot be predicted or reproduced by attackers

## Remediation Steps

- Identify weak randomness - Review flaw details for file/line using general-purpose random functions, time()-based seeds, or timestamp values (see the language-specific guidance's Taint Sinks for concrete function names)
- Determine usage context - Check if random values are used for encryption keys, IVs/nonces, session tokens, CSRF tokens, or API keys
- Replace with CSPRNG - Use the platform or language's cryptographically secure random source (see the language-specific guidance's Safe Pattern for concrete APIs)
- Validate entropy length - Ensure generated values meet minimum bit requirements for their security purpose
- Test unpredictability - Verify that sequential calls produce non-repeating, non-sequential values
- Remove weak sources - Eliminate all references to insecure random functions in security-critical code paths
