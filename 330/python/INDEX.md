# CWE-330: Use of Insufficiently Random Values - Python

## LLM Guidance

Weak random number generation occurs when the `random` module is used for security-sensitive operations like session tokens, API keys, or cryptographic values. The `random` module uses the Mersenne Twister algorithm, which is deterministic and predictable if an attacker observes outputs or guesses the seed. For security purposes, always use the `secrets` module (Python 3.6+) or `os.urandom()`, which provide cryptographically secure randomness.

## Key Principles

- Never use `random` module for security-sensitive operations (tokens, keys, passwords, nonces)
- Use `secrets` module for all cryptographic operations requiring unpredictability
- Ensure minimum 256 bits of entropy for tokens and keys
- Prefer built-in methods: `secrets.token_urlsafe()`, `secrets.token_hex()`, `secrets.token_bytes()`
- Use `secrets.choice()` for random selection from sequences in security contexts

## Taint Sinks

`random.random()`, `random.choice()`, `random.randint()`, `random.seed()`

## Remediation Steps

- Replace `random.choice()` with `secrets.choice()` for character selection
- Replace `random.randint()` with `secrets.randbelow()` for integer generation
- Use `secrets.token_urlsafe(32)` for URL-safe tokens with 256-bit entropy
- Use `secrets.token_hex(32)` for hexadecimal tokens
- Audit all uses of `random` module and migrate security-critical operations
- Add validation to ensure tokens meet minimum entropy requirements
