# CWE-328: Use of Weak Hash

## LLM Guidance

A child of CWE-327 where the weakness is the hash itself. Collision resistance breaks first - MD5 and SHA-1 have practical collisions and no practical preimage attack - so a digest no longer pins the input that produced it. A fast hash used for password storage is CWE-916 instead, where the speed rather than the algorithm is the defect.

## Key Principles

- Use purpose-appropriate hashing - bcrypt/Argon2 for passwords, SHA-256+ for integrity
- Separate this from CWE-916: here the hash function itself is broken, so MD5 or SHA-1 fails for
  integrity and signatures as well as for passwords. Where the algorithm is sound and the defect is
  that it is fast or unsalted - a plain SHA-256 password digest - CWE-916 is the closer entry, and the
  fix is a work factor rather than a different digest
- Never use fast hashes (MD5, SHA-1, plain SHA-256) for password storage; use purpose-specific hashes for other security operations
- Apply key derivation functions with sufficient work factors: OWASP's current Password Storage
  Cheat Sheet gives bcrypt a minimum cost of 10 and PBKDF2-HMAC-SHA256 a recommended 600,000
  iterations - treat these as floors, and raise them where server performance allows
- Upgrade legacy systems by rehashing on user login without forcing password resets
- Use SHA-256 or SHA-3 for file integrity, digital signatures, and non-password use cases

## Remediation Steps

- Identify weak hash usage - Review flaw details for file/line using MD5, SHA-1, or plain SHA-256; determine purpose (passwords, integrity, signatures)
- Replace password hashing - Migrate to bcrypt (cost 10+), Argon2id, or PBKDF2-HMAC-SHA256 (600,000 iterations); never use fast hashes for passwords
- Upgrade integrity checks - Replace MD5/SHA-1 with SHA-256, SHA-384, or SHA-3 for file verification and checksums
- Update cryptographic operations - Use SHA-256+ for HMACs, digital signatures, and key derivations
- Test thoroughly - Verify backward compatibility, test authentication flows, and validate integrity checks with new algorithms
- Deploy rehashing strategy - For legacy systems, rehash passwords during user login to migrate gradually without forcing resets
