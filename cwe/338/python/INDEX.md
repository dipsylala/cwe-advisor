# CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG) - Python

## LLM Guidance

Use of Cryptographically Weak PRNG occurs when developers use Python's `random` module (Mersenne Twister algorithm) for security-sensitive operations like generating tokens, passwords, or encryption keys. This module is predictable and allows attackers to forecast generated values.

**Primary Defence:** Use `secrets` module (Python 3.6+) for all security-sensitive randomness.

## Key Principles

- Replace `random` module with `secrets` module for tokens, passwords, keys, and security identifiers
- Use `secrets.token_bytes()`, `secrets.token_hex()`, or `secrets.token_urlsafe()` for cryptographic randomness
- Reserve `random` module only for non-security contexts like simulations, games, or testing
- Use `os.urandom()` directly only where lower-level bytes are actually needed instead of a token or a bounded integer; `secrets` requires Python 3.6+, which every currently supported CPython release satisfies
- Compare a generated secret with `secrets.compare_digest()` - generating it strongly and then comparing it with `==` leaves a timing channel

## Taint Sinks

`random.random()`, `random.randint()`, `random.choice()`, `random.getrandbits()`

## Remediation Steps

- Identify all `import random` statements and audit usage for security contexts
- Replace `random.randint()`, `random.choice()`, `random.random()` with `secrets` equivalents
- For session tokens - use `secrets.token_urlsafe(32)` (generates 32-byte URL-safe string)
- For numeric secrets - `secrets.randbelow(n)` takes one argument and returns `0 <= N < n`, so it is a direct swap only for `random.randint(0, n-1)`; a general `random.randint(a, b)` needs `a + secrets.randbelow(b - a + 1)` to preserve the original range, since `randbelow` has no parameter for the lower bound
- For password generation - use `secrets.choice()` with character sets
- Verify changes don't affect non-security code that legitimately uses `random`
