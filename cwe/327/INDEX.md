# CWE-327: Use of a Broken or Risky Cryptographic Algorithm

## LLM Guidance

Weak or broken cryptographic algorithms fail to protect data confidentiality, integrity, and authenticity. Modern computing power can break algorithms like MD5, DES, and SHA-1 in seconds to minutes, allowing attackers to decrypt data, forge signatures, or crack passwords. Applications must use strong, modern cryptographic standards to ensure security.

## Key Principles

- Do not use broken or deprecated cryptography (MD5, DES, 3DES, SHA-1, RC4)
- Cryptographic algorithm selection must be centrally defined and server-controlled
- Use only algorithms that remain cryptographically sound with current computing power
- Separate concerns: use encryption for confidentiality, hashing for integrity, and password hashing for credential storage
- Configure TLS/SSL to use modern protocols (TLS 1.2+) and strong cipher suites
- Be precise about what is broken: MD5 and SHA-1 have practical *collision* attacks, so a digest no longer pins the input that produced it, but neither has a practical preimage attack - a password digest under them is not recovered by breaking the hash, and the separate reason fast hashes fail there is CWE-916, which has no entry here - the password-hashing guidance lives under CWE-328. CRC32 is not a cryptographic hash at all
- Static RSA key exchange has no forward secrecy, so one leaked private key decrypts every session ever recorded, and its PKCS#1 v1.5 padding has repeatedly produced Bleichenbacher oracles; anonymous DH authenticates nobody, and export-grade suites exist to be downgraded into (FREAK, Logjam)
- RSA and ECC keys are not brute-forced key by key - RSA falls to factoring and ECC to discrete-log algorithms - which is why an RSA key must be an order of magnitude longer for the same strength
- Version the ciphertext and dispatch on that metadata when migrating; a dual-read that decides by "did the decrypt throw" only works against an authenticated mode, since a wrong-key AES-CBC decrypt yields valid PKCS#7 padding about 0.4% of the time and a large table then re-encrypts thousands of garbage rows

## Remediation Steps

- Identify the weak algorithm in use (DES, MD5, SHA-1, etc.) from flaw details including file and line number
- Determine the cryptographic purpose - encryption, hashing, password hashing, digital signatures, or TLS configuration
- Replace weak algorithms with approved alternatives - AES-256-GCM for encryption, SHA-256/SHA-3 for hashing, bcrypt/Argon2 for passwords
- Update TLS/SSL configurations to disable outdated protocols (SSL, TLS 1.0/1.1) and weak cipher suites
- Use vetted, currently supported cryptographic libraries (NaCl, libsodium, OpenSSL 3.x/4.x or vendor-supported builds) rather than implementing custom cryptography
- Test thoroughly to ensure the replacement algorithm functions correctly without breaking existing functionality
