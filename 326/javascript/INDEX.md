# CWE-326: Inadequate Encryption Strength - JavaScript

## LLM Guidance

Inadequate Encryption Strength in JavaScript/Node.js applications occurs when developers use weak cryptographic algorithms (MD5, DES, RC4), insufficient key sizes, or deprecated ciphers that fail to protect sensitive data against modern attacks. The Node.js `crypto` module provides both secure and insecure options-always use AES-256-GCM, ChaCha20-Poly1305, or modern algorithms with proper key derivation (PBKDF2, scrypt, Argon2).

## Key Principles

- Use AES-256-GCM or ChaCha20-Poly1305 for symmetric encryption with authenticated encryption modes
- Generate keys with cryptographically secure random sources (`crypto.randomBytes()`) at minimum 256-bit length
- Derive keys from passwords using PBKDF2 (600,000+ iterations), scrypt, or Argon2
- Avoid deprecated algorithms: DES, 3DES, RC4, MD5, SHA1, AES-ECB mode
- Compare secrets with `crypto.timingSafeEqual()`, which requires equal-length buffers and throws otherwise - hash both sides first where the lengths can differ
- `bcrypt.compare()` performs its own constant-time comparison, so the remaining exposure is the surrounding control flow rather than the digest check

## Taint Sinks

`crypto.createCipheriv('des...')`, `crypto.createCipheriv('aes-128-ecb', ...)`, `crypto.createHash('md5')`, `crypto.createHash('sha1')`

## Remediation Steps

- Replace weak ciphers (DES, RC4, ECB, CBC without authentication, or sub-128-bit/policy-disallowed keys) with AES-GCM or ChaCha20-Poly1305
- Generate 256-bit keys using `crypto.randomBytes(32)` or derive from passwords with `crypto.pbkdf2()` (600,000+ iterations)
- Use authenticated encryption modes (GCM, CCM) that provide both confidentiality and integrity
- Generate unique IVs/nonces per encryption operation using `crypto.randomBytes(12)` for GCM
- Store salt, IV, ciphertext, and the `cipher.getAuthTag()` value (readable only after `cipher.final()`) together; never hardcode encryption keys
