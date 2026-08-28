# CWE-326: Inadequate Encryption Strength - Java

## LLM Guidance

Inadequate Encryption Strength in Java occurs when weak cryptographic algorithms (DES, RC4, MD5), insufficient key sizes (<128-bit for symmetric, <2048-bit for RSA), or deprecated ciphers are used, leaving data vulnerable to brute-force and cryptanalytic attacks. The core fix is to use strong, modern algorithms (AES-256, RSA-2048+, SHA-256+) with proper key generation from secure random sources via Java's JCA/JCE framework.

## Key Principles

- Default new symmetric encryption code to AES-256; AES-128 is an acceptable NIST-approved floor only where a specific constraint requires it. Use RSA with minimum 2048-bit keys for asymmetric encryption
- Generate cryptographic keys using `SecureRandom` with proper entropy, never hardcode or derive from weak sources
- Specify complete cipher transformations including mode and padding (e.g., "AES/GCM/NoPadding") to avoid insecure defaults
- Use authenticated encryption modes (GCM, CCM) that provide both confidentiality and integrity protection
- Regularly update to latest JDK versions to benefit from security patches and modern algorithm support

## Taint Sinks

`Cipher.getInstance("DES")`, `Cipher.getInstance("AES")` (no mode/padding, defaults to ECB), `MessageDigest.getInstance("MD5")`, `MessageDigest.getInstance("SHA-1")`, `KeyPairGenerator.getInstance("RSA").initialize(1024)` (below the 2048-bit minimum)

## Remediation Steps

- Replace DES, 3DES, RC4, Blowfish with AES-256; replace MD5, SHA-1 with SHA-256 or SHA-512
- Update `KeyGenerator.getInstance()` calls to specify explicit key sizes - default to 256 for AES (128 remains acceptable only where a specific constraint requires it), and 2048+ for RSA
- Change cipher initialization to use explicit modes - prefer "AES/GCM/NoPadding" over "AES", initialized with a `GCMParameterSpec(128, iv)` (128-bit tag) over a fresh 12-byte `SecureRandom` IV
- Replace `new Random()` or `Math.random()` with `SecureRandom` for all cryptographic operations
- Review and update key storage mechanisms to use Java KeyStore with strong passwords
- Add cipher strength validation in security configuration or startup checks
