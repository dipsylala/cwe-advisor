# CWE-347: Improper Verification of Cryptographic Signature

## LLM Guidance

Improper signature verification occurs when applications accept unsigned data, fail to validate signatures, use weak signature algorithms, or implement flawed verification logic. This enables attackers to forge signatures, tamper with signed data, and bypass authentication mechanisms.

## Key Principles

- Verify all signatures before trusting data - Never skip verification or accept unsigned data
- Use strong, approved signature algorithms - Reject weak algorithms (MD5, SHA1) and "alg=none"
- Validate complete certificate chains - Check validity, revocation status, and trust anchors
- Fail securely on verification errors - Reject data immediately on any verification failure
- Apply canonical forms before verification - Prevent signature bypass via data manipulation
- Establish what the installed library already refuses before writing anything: mint the forged token the finding describes and feed it to the current code. If it is already rejected, the described weakness is not the one present, and fixing it changes nothing
- Allowlist the exact algorithm, not the family - an `RSA` or `HMAC` family check still admits every digest size in that family, which is the gap that survives on most current libraries, and a resolver that returns a different *key type* depending on the header performs the confusion itself
- Fix the key before reading the token: the verification key comes from configuration, a keystore, or a JWKS cache the application fetched, never from the token
- Act on the bytes that were verified rather than a second copy: parse the same raw bytes the signature covered, and for XML confirm the validated `<Reference>` covers the element you go on to read
- Compare raw signatures and HMACs with the runtime's constant-time function - none of them is `==` - and check what it does on a *length* mismatch as well as a value mismatch
- If an environment-gated bypass exists, ask which branch an *unset* variable selects; "not production" is the usual answer and the dangerous one

## Remediation Steps

- Locate the vulnerability - Review flaw details to identify missing or improper signature verification in your code
- Identify the signature type - Determine what's affected - JWTs, API signatures, certificates, software updates, or documents
- Implement mandatory verification - Always verify signatures before trusting data; never accept unsigned content
- Use approved algorithms - Enforce strong algorithms (RSA-PSS, ECDSA with SHA-256+); reject weak or "none" algorithms
- Validate certificate chains - Check issuer validity, expiration dates, and revocation status (CRL/OCSP)
- Fail securely - Reject data immediately on any verification failure; log security events for monitoring
