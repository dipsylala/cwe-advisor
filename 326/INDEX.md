# CWE-326: Inadequate Encryption Strength

## LLM Guidance

Inadequate Encryption Strength occurs when cryptographic algorithms or key sizes are too weak to provide effective protection, allowing attackers to break encryption and access sensitive data. The core fix is to use strong, industry-standard algorithms with appropriate key sizes and ensure cryptographic strength is server-controlled, not determined by legacy compatibility or client input.

## Key Principles

- Never allow cryptographic strength to be determined by legacy compatibility or client input
- Cryptographic algorithms, protocols, and key sizes must be centrally defined and server-controlled
- Constrain all cryptographic operations to secure minimums based on current industry standards
- Replace weak algorithms (DES, 3DES, RC4, MD5, SHA-1) with strong alternatives (AES-GCM/ChaCha20-Poly1305, SHA-256/SHA-3)

## Remediation Steps

- Review flaw details to identify where weak cryptographic algorithms or key sizes are used in your code
- Identify weak algorithms - DES, 3DES, RC4, MD5, SHA-1, ECB mode, CBC without authentication, or policy-disallowed key sizes
- Verify minimum key sizes - RSA ≥ 2048 bits, AES ≥ 128 bits (256 where policy requires it), ECC ≥ 256 bits
- Use authenticated encryption such as AES-128-GCM, AES-256-GCM, or ChaCha20-Poly1305
- Use SHA-256 or SHA-3 for hashing (not MD5 or SHA-1)
- Implement centralized cryptographic configuration that enforces secure algorithm and key size minimums
