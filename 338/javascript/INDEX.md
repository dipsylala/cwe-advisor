# CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG) - JavaScript

## LLM Guidance

`Math.random()` is not cryptographically secure and must never be used for security-sensitive operations like generating tokens, keys, passwords, or session IDs. Attackers can predict these values to compromise authentication, sessions, or encryption. Always use Node.js `crypto` module functions (`crypto.randomBytes()`, `crypto.randomInt()`) sized for at least 256 bits of entropy for security-critical randomness; `crypto.randomUUID()` is cryptographically random but only carries 122 bits of entropy (UUIDv4), so reserve it for non-secret unique identifiers, not session tokens, API keys, or other bearer secrets.

## Key Principles

- Replace all `Math.random()` calls in security contexts with `crypto.randomBytes()` or equivalent
- Use `crypto.randomBytes(32)` for session tokens and API keys - `crypto.randomUUID()`'s 122 bits of entropy is weaker than the 256-bit minimum expected of bearer secrets; reserve it for non-secret unique identifiers
- Use `crypto.randomInt()` for random integers in security-sensitive ranges
- Keep `Math.random()` only for non-security purposes (animations, game mechanics, UI randomization)
- Validate that random values have sufficient entropy for their security purpose

## Remediation Steps

- Identify all uses of `Math.random()` in authentication, session management, encryption, and token generation
- Replace with appropriate `crypto` module function based on use case
- Ensure random byte buffers are converted to appropriate formats (hex, base64, base64url)
- Add length validation to ensure sufficient entropy (minimum 16 bytes for tokens)
- Test that changes don't break existing functionality
- Review for indirect uses through utility functions or third-party libraries

## Safe Pattern

```javascript
const crypto = require('crypto');

// Generate secure random token (32 bytes = 256 bits)
function generateSecureToken() {
  return crypto.randomBytes(32).toString('base64url');
}

// Generate secure session ID (256 bits - do not use crypto.randomUUID() here,
// its 122 bits of entropy is too weak for a bearer token)
function generateSessionId() {
  return crypto.randomBytes(32).toString('base64url');
}

// Generate random integer for OTP
function generateOTP() {
  return crypto.randomInt(100000, 999999);
}
```
