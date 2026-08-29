# CWE-326: Inadequate Encryption Strength

## LLM Guidance

Inadequate Encryption Strength is a choice made once and never revisited: an algorithm or key size too weak for the data's lifetime, often still reachable through a legacy compatibility branch. Fix by making the decision central and server-controlled, and check each finding against the standard's actual status word first - several flagged algorithms are restricted for one operation and permitted for another, so treating a partial restriction as total turns working code into a false finding.

## Key Principles

- Size keys by security strength, not digit count. NIST SP 800-57 Part 1 Rev. 5 Table 2 places RSA-3072, a 256-bit elliptic curve and AES-128 at the same 128-bit level, so an EC key is roughly twice the length of the strength it delivers. The table steps straight from RSA-3072 to RSA-7680, so any strength figure quoted for RSA-4096 is extrapolation rather than a published value
- RSA-2048 is 112-bit strength: acceptable for applying protection through 2030, disallowed from 2031, with already-protected data still processable as legacy use. This governs new key material; it is not a mandate to re-encrypt or re-sign what exists
- AES-128 is not a finding on its own: NIST rates AES-128, AES-192 and AES-256 alike as acceptable with no end date. Prefer AES-256 in new code as margin, not because 128 is disallowed
- Read the operation, not just the algorithm name. 3DES is disallowed for encryption after 31 December 2023 but permitted for decryption as legacy use; SHA-1 is disallowed for signature generation, legacy use for verification, and still acceptable in non-signature applications until NIST's stated retirement date of 31 December 2030
- Pick hashes by output length, not family - SHA-3 is an approved alternative to SHA-2 rather than its successor, and the 224-bit members of both sit on the same deprecation path as SHA-1
- Use authenticated encryption (AES-GCM, ChaCha20-Poly1305). CBC without a MAC verified before decryption is a padding-oracle vector, not just a weaker mode
- For password hashing OWASP prescribes Argon2id (19 MiB, 2 iterations, 1 degree of parallelism); scrypt where Argon2id is unavailable (N=2^17, r=8, p=1); bcrypt for legacy systems only, at work factor 10 or more with its 72-byte input limit; and PBKDF2-HMAC-SHA256 at 600,000 iterations where FIPS-140 compliance is required - a branch selected by compliance regime, not a last resort. Iteration counts are stated per HMAC, so a count quoted for one digest does not carry to another

## Remediation Steps

- Identify which operation the finding sits on and confirm the algorithm is disallowed for it, then trace what the value protects and for how long - a session token and a decade-retained record justify different margins
- Replace the primitive: DES, 3DES, RC4 and ECB with an AEAD mode; MD5 and SHA-1 with SHA-256 or a SHA-3 variant of 256 bits or more; a bare password digest with the OWASP algorithm above
- Centralize the choice in one helper so call sites cannot select a weaker cipher, and delete the legacy branch rather than leaving it unreachable
- Keep a dual-read path for data already protected under the old algorithm. Swapping the cipher and shipping makes existing records undecryptable, and the change passes review because the new path works - test it against a fixture encrypted under the old one. Password hashes are the easier case: wrap the strong function around the stored digest and re-derive at next login, then assert the stored hash was rewritten rather than merely verified
- Verify that identical plaintexts produce different ciphertexts, that a tampered ciphertext fails authentication, and that the weak path is gone rather than unused
