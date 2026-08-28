# CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG) - Python

## LLM Guidance

Use of Cryptographically Weak PRNG occurs when developers use Python's `random` module (Mersenne Twister algorithm) for security-sensitive operations like generating tokens, passwords, or encryption keys. This module is predictable and allows attackers to forecast generated values.

**Primary Defence:** Use `secrets` module (Python 3.6+) for all security-sensitive randomness.

## Key Principles

- Replace `random` module with `secrets` module for tokens, passwords, keys, and security identifiers
- Use `secrets.token_bytes()`, `secrets.token_hex()`, or `secrets.token_urlsafe()` for cryptographic randomness
- Reserve `random` module only for non-security contexts like simulations, games, or testing
- Use `os.urandom()` as fallback for Python < 3.6 or lower-level randomness needs
- Compare a generated secret with `secrets.compare_digest()` - generating it strongly and then comparing it with `==` leaves a timing channel

## Taint Sinks

`random.random()`, `random.randint()`, `random.choice()`, `random.getrandbits()`

## Remediation Steps

- Identify all `import random` statements and audit usage for security contexts
- Replace `random.randint()`, `random.choice()`, `random.random()` with `secrets` equivalents
- For session tokens - use `secrets.token_urlsafe(32)` (generates 32-byte URL-safe string)
- For numeric secrets - use `secrets.randbelow(n)` instead of `random.randint(0, n-1)`
- For password generation - use `secrets.choice()` with character sets
- Verify changes don't affect non-security code that legitimately uses `random`
