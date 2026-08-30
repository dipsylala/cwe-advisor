# CWE-780: Use of RSA Algorithm without OAEP - JavaScript

## LLM Guidance

RSA encryption without OAEP (Optimal Asymmetric Encryption Padding) is vulnerable to padding oracle attacks and chosen ciphertext attacks. Node's `crypto.publicEncrypt()`/`crypto.privateDecrypt()` already default `padding` to `crypto.constants.RSA_PKCS1_OAEP_PADDING` - the finding here is almost always an explicit `padding: crypto.constants.RSA_PKCS1_PADDING` override, not a silently-insecure default. The live default worth fixing is `oaepHash`, which defaults to `'sha1'` when OAEP padding is used without it set explicitly.

## Key Principles

- Do not add `padding: crypto.constants.RSA_PKCS1_OAEP_PADDING` as if it were missing - it is already the default for `publicEncrypt`/`privateDecrypt` when `padding` is unset; the code to look for is an explicit override to `RSA_PKCS1_PADDING` or `RSA_NO_PADDING`
- Always set `oaepHash: 'sha256'` (or stronger) explicitly - the OAEP default hash is SHA-1 whether or not `padding` was set
- Use 3072-bit RSA keys for new key generation (NIST SP 800-57 Part 1 disallows 2048-bit/112-bit-strength RSA after 2030); 4096-bit for long-term security, 2048 only on an existing key not yet due for rotation
- Prefer modern alternatives like AES-GCM with RSA-OAEP for hybrid encryption
- `subtle.encrypt`/`decrypt` with an OAEP `CryptoKey` is the WebCrypto form; on the Node side, do not surface `ERR_OSSL_RSA_OAEP_DECODING_ERROR` to the caller, since a distinguishable decode failure is the oracle the attack needs

## Taint Sinks

`crypto.publicEncrypt()`, `crypto.privateDecrypt()` with `padding: crypto.constants.RSA_PKCS1_PADDING`

## Remediation Steps

- Locate all `crypto.publicEncrypt()` and `crypto.privateDecrypt()` calls
- Trace data flow - check whether `padding` is set at all; if so, confirm it is not `RSA_PKCS1_PADDING`/`RSA_NO_PADDING`, and check `oaepHash` regardless
- Add explicit `oaepHash: 'sha256'` to every call's options, and remove any `padding: crypto.constants.RSA_PKCS1_PADDING` override
- Verify RSA key size is 3072 bits for a new key, not just 2048
- Test encryption/decryption with OAEP padding enabled
- Review and update all RSA encryption configurations
- Regenerate any data encrypted with PKCS#1 v1.5 padding
