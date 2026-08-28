# CWE-261: Weak Encoding for Password

## LLM Guidance

Weak encoding schemes (Base64, XOR, ROT13, URL encoding) are not cryptography and provide zero security. Encoded passwords are trivially reversible and offer no protection. Use strong cryptographic password hashing algorithms (bcrypt, Argon2, PBKDF2) instead of encoding.

## Key Principles

- Replace all encoding with proper cryptographic password hashing
- Use adaptive hashing algorithms with appropriate work factors
- Store only password hashes, never plaintext or encoded passwords
- Implement secure password comparison using constant-time functions
- Use password salting to prevent rainbow table attacks
- An encoding has no key, and where the transform does take one - an XOR against a constant - that key sits in the repository beside the code that applies it, which comes to the same thing
- The verification step gives the finding away: code that decodes the stored value in order to compare it has stored the password, written differently
- The migration differs from the plaintext case: an encoded column must be decoded before it is hashed, so it cannot be hashed in place the way CWE-256's column can
- If the stored value can be recovered by a known fixed procedure rather than brute-forced, the finding is this one and not the weak-hashing family (CWE-916, CWE-759, CWE-760)

## Remediation Steps

- Identify weak encoding patterns - Search for `btoa()`, `atob()`, `base64_encode()`, `base64.b64encode()` in password handling code
- Check for XOR operations - Find XOR operations applied to password strings or static key obfuscation
- Review database schemas - Look for VARCHAR/TEXT password columns indicating reversible storage
- Locate reversible operations - Find URL encoding, hex encoding, or other reversible transformations on passwords
- Replace with strong hashing - Implement bcrypt, Argon2, or scrypt with appropriate cost parameters
- Update password comparison logic - Use hash verification functions instead of decoded string comparisons
