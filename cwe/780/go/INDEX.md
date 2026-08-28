# CWE-780: Use of RSA Algorithm without OAEP - Go

## LLM Guidance

Go's `crypto/rsa` package exposes both the insecure `rsa.EncryptPKCS1v15`/`rsa.DecryptPKCS1v15` functions and the secure `rsa.EncryptOAEP`/`rsa.DecryptOAEP` functions side by side, so migration is a direct function swap plus an explicit hash parameter. Replace any PKCS#1 v1.5 call with OAEP using SHA-256 (`crypto/sha256`). For RSA signing, use `rsa.SignPSS` instead of `rsa.SignPKCS1v15` - PSS is the analogous safe choice for signatures, distinct from OAEP which applies to encryption. RSA-OAEP can only encrypt small payloads (roughly key-size-in-bytes minus 2x hash-size minus 2), so use hybrid encryption for anything larger: encrypt the payload with AES-GCM and encrypt only the AES key with RSA-OAEP.

## Key Principles

- Use `rsa.EncryptOAEP` / `rsa.DecryptOAEP` with `sha256.New()` (or better) instead of `rsa.EncryptPKCS1v15` / `rsa.DecryptPKCS1v15`
- For signatures, use `rsa.SignPSS` / `rsa.VerifyPSS` instead of `rsa.SignPKCS1v15` / `rsa.VerifyPKCS1v15`
- Never return the raw error from `rsa.DecryptOAEP` to a caller or vary logging/response behavior by failure type - doing so can reintroduce a padding-oracle-style distinguishing signal
- Use hybrid encryption (AES-256-GCM for data, RSA-OAEP for the AES key) for payloads larger than the OAEP size limit rather than chunking with repeated RSA calls
- Always source randomness for `rsa.EncryptOAEP` from `crypto/rand.Reader`, never `math/rand` or a deterministic reader, even in test helpers that could get reused elsewhere
- Use RSA keys of at least 2048 bits (4096 for long-lived keys)

## Taint Sinks

`rsa.EncryptPKCS1v15()`, `rsa.DecryptPKCS1v15()`, `rsa.SignPKCS1v15()`, `rsa.VerifyPKCS1v15()`

## Remediation Steps

- Locate - Search for `rsa.EncryptPKCS1v15`, `rsa.DecryptPKCS1v15`, `rsa.SignPKCS1v15`, or `rsa.VerifyPKCS1v15` calls in the codebase
- Trace data flow - Confirm which calls encrypt/decrypt data versus sign/verify - each needs a different OAEP/PSS replacement
- Replace the unsafe pattern - Swap encryption calls to `rsa.EncryptOAEP`/`rsa.DecryptOAEP` with `sha256.New()`; swap signing calls to `rsa.SignPSS`/`rsa.VerifyPSS`
- Bind, encode, validate, or authorize - For payloads exceeding the OAEP size limit, generate a random AES-256 key, encrypt data with AES-GCM, and encrypt only the AES key with `rsa.EncryptOAEP`
- Harden configuration - Ensure `rand.Reader` (`crypto/rand`) is used for all key generation and encryption calls, and confirm key size is at least 2048 bits via `rsa.GenerateKey`
- Test - Round-trip encrypt/decrypt and sign/verify with valid and corrupted ciphertexts/signatures, confirming errors are generic and non-distinguishing
