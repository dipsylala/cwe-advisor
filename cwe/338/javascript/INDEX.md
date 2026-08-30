# CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG) - JavaScript

## LLM Guidance

`Math.random()` is not cryptographically secure and must never be used for security-sensitive operations like generating tokens, keys, passwords, or session IDs. Attackers can predict these values to compromise authentication, sessions, or encryption. Always use Node.js `crypto` module functions (`crypto.randomBytes()`, `crypto.randomInt()`), sized to at least 128 bits for tokens and session IDs and 256 bits for symmetric key material - the two are not the same floor. `crypto.randomUUID()` is cryptographically random but only carries 122 bits of entropy (UUIDv4), so reserve it for non-secret unique identifiers, not session tokens, API keys, or other bearer secrets.

## Key Principles

- Replace all `Math.random()` calls in security contexts with `crypto.randomBytes()` or equivalent
- Use `crypto.randomBytes(16)` (128 bits) for session tokens and CSRF tokens, and `crypto.randomBytes(32)` (256 bits) for API keys and symmetric key material - `crypto.randomUUID()`'s 122 bits sits below even the token floor, so reserve it for non-secret unique identifiers
- Use `crypto.randomInt()` for random integers in security-sensitive ranges; its documented range is exclusive of `max` and must span less than 2^48
- Keep `Math.random()` only for non-security purposes (animations, game mechanics, UI randomization)
- Validate that random values have sufficient entropy for their security purpose
- Compare a generated secret with `crypto.timingSafeEqual()` on equal-length buffers - generating it strongly and then comparing it with `===` leaves a timing channel. It throws `RangeError [ERR_CRYPTO_TIMING_SAFE_EQUAL_LENGTH]` rather than returning `false` when the buffers differ in length, so a caller comparing against attacker-controlled input needs a length check first or the comparison fails closed by exception rather than by result

## Taint Sinks

`Math.random()`

## Remediation Steps

- Identify all uses of `Math.random()` in authentication, session management, encryption, and token generation
- Replace with appropriate `crypto` module function based on use case
- Ensure random byte buffers are converted to appropriate formats (hex, base64, base64url)
- Add length validation to ensure sufficient entropy: 16+ bytes for tokens and session IDs, 32+ bytes for key material
- Test that changes don't break existing functionality
- Review for indirect uses through utility functions or third-party libraries
