# CWE-916: Use of Password Hash With Insufficient Computational Effort

## LLM Guidance

Weak password hashing uses fast cryptographic functions (MD5, SHA-1, SHA-256) or poorly configured algorithms that attackers can brute-force when database dumps are compromised. Password hashing requires intentionally slow, computationally expensive algorithms designed specifically for password storage to resist offline cracking attacks. Use adaptive algorithms like Argon2id, bcrypt, or scrypt with work factors tuned to current hardware.

## Key Principles

- Use adaptive, purpose-built password hashing algorithms (Argon2id, bcrypt, scrypt)
- Never use fast general-purpose hashes (MD5, SHA-1, SHA-256) for passwords
- Tune work factors to current hardware (target 250-500ms per hash)
- Balance security (slow enough to resist brute force) with usability (fast enough for legitimate authentication)
- Implement password migration strategy when upgrading from weak algorithms
- Tune the work factor on production-class hardware to a target cost (250-500ms per hash) rather than copying a number, and remember that raising it later applies to *new* hashes only - the plaintext needed to re-hash an existing one is gone, so each stored password upgrades at that user's next successful login
- Choose in OWASP's order and know why: Argon2id first (memory-hard and side-channel resistant together), scrypt where it is unavailable, bcrypt only for legacy systems (CPU-hard but not memory-hard, and it carries an input-length trap), and PBKDF2 where FIPS-140 validation is required
- No salt at all is CWE-759 and a predictable or shared salt is CWE-760; this entry is the broader insufficient-effort weakness, salted or not

## Remediation Steps

- Identify the weak hashing algorithm in use (MD5, SHA-1, SHA-256, unsalted hash)
- Review flaw details for specific file, line number, and code pattern
- Trace password flow from user registration/login through hashing to storage
- Check database schema for password hash column and verify salt storage
- Replace weak algorithm with Argon2id (preferred), bcrypt, or scrypt
- Configure appropriate work factors and migrate existing password hashes
