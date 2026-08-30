# CWE-780: Use of RSA Algorithm without OAEP - Go

## LLM Guidance

Go's `crypto/rsa` package exposes both `rsa.EncryptPKCS1v15`/`rsa.DecryptPKCS1v15`, which Go's own doc comments mark deprecated ("PKCS #1 v1.5 encryption is dangerous and should not be used"), and the secure `rsa.EncryptOAEP`/`rsa.DecryptOAEP` side by side, so migration is a direct function swap plus an explicit hash parameter. Replace any PKCS#1 v1.5 encryption call with OAEP using SHA-256 (`crypto/sha256`). CWE-780 is specifically about encryption padding - `rsa.SignPKCS1v15`/`rsa.VerifyPKCS1v15` are a different scheme (signatures, not encryption) and are not deprecated by Go; PKCS#1 v1.5 signing remains the standard most X.509 certificates and TLS handshakes use, so finding it in code is not itself this CWE's finding. RSA-OAEP can only encrypt small payloads (roughly key-size-in-bytes minus 2x hash-size minus 2), so use hybrid encryption for anything larger: encrypt the payload with AES-GCM and encrypt only the AES key with RSA-OAEP.

## Key Principles

- Use `rsa.EncryptOAEP` / `rsa.DecryptOAEP` with `sha256.New()` (or better) instead of `rsa.EncryptPKCS1v15` / `rsa.DecryptPKCS1v15` - the encryption pair is what Go's own docs deprecate for this CWE
- `rsa.SignPKCS1v15`/`rsa.VerifyPKCS1v15` are not this CWE's finding - they are undeprecated, standard-scheme signature functions; do not flag ordinary signing code that uses them. Where a project is choosing a signature scheme for new code, `rsa.SignPSS`/`rsa.VerifyPSS` is a reasonable preference, but replacing existing PKCS1v15 signing is a different, weaker-motivated change than the encryption fix above
- Never return the raw error from `rsa.DecryptOAEP` to a caller or vary logging/response behavior by failure type - doing so can reintroduce a padding-oracle-style distinguishing signal
- Use hybrid encryption (AES-256-GCM for data, RSA-OAEP for the AES key) for payloads larger than the OAEP size limit rather than chunking with repeated RSA calls
- Always source randomness for `rsa.EncryptOAEP` from `crypto/rand.Reader`, never `math/rand` or a deterministic reader, even in test helpers that could get reused elsewhere
- Use 3072-bit RSA keys for new key generation (NIST SP 800-57 Part 1 disallows 2048-bit/112-bit-strength RSA after 2030); 4096 for long-lived keys, 2048 only on an existing key not yet due for rotation

## Taint Sinks

`rsa.EncryptPKCS1v15()`, `rsa.DecryptPKCS1v15()`

## Remediation Steps

- Locate - Search for `rsa.EncryptPKCS1v15` or `rsa.DecryptPKCS1v15` calls in the codebase (not `SignPKCS1v15`/`VerifyPKCS1v15` - those are a different, non-deprecated scheme)
- Trace data flow - Confirm the finding is encryption, not a signature verification path that happens to use the PKCS1v15-named functions
- Replace the unsafe pattern - Swap encryption calls to `rsa.EncryptOAEP`/`rsa.DecryptOAEP` with `sha256.New()`
- Bind, encode, validate, or authorize - For payloads exceeding the OAEP size limit, generate a random AES-256 key, encrypt data with AES-GCM, and encrypt only the AES key with `rsa.EncryptOAEP`
- Harden configuration - Ensure `rand.Reader` (`crypto/rand`) is used for all key generation and encryption calls, and confirm key size is at least 2048 bits via `rsa.GenerateKey`
- Test - Round-trip encrypt/decrypt and sign/verify with valid and corrupted ciphertexts/signatures, confirming errors are generic and non-distinguishing
