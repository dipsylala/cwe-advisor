# CWE-780: Use of RSA Algorithm without OAEP - Java

## LLM Guidance

Using RSA encryption without OAEP (Optimal Asymmetric Encryption Padding) enables padding oracle attacks, chosen ciphertext attacks, and message malleability. In Java, this commonly occurs when using `Cipher.getInstance("RSA")` without specifying the padding mode, which defaults to the insecure PKCS#1 v1.5 padding. Always use `Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")` with explicit OAEP parameters.

## Key Principles

- Always specify the complete cipher transformation string including OAEP padding mode
- Use SHA-256 or stronger hash functions for OAEP (avoid SHA-1)
- Configure `OAEPParameterSpec` explicitly with MGF1 and appropriate hash algorithm - do not reach for `OAEPParameterSpec.DEFAULT` thinking the name implies a safe default: it is SHA-1-based and has been `@Deprecated(since="19")` for exactly that reason
- Use 3072-bit RSA keys for new key generation (NIST SP 800-57 Part 1 disallows 2048-bit/112-bit-strength RSA after 2030); 4096 recommended for sensitive data, 2048 only on an existing key not yet due for rotation
- Do not report the difference: `BadPaddingException` and `IllegalBlockSizeException` distinguish "padding parsed" from "it did not", which is exactly the oracle the attack needs - catch both, return one generic failure, and log the detail server-side

## Taint Sinks

`Cipher.getInstance("RSA")`, `Cipher.getInstance("RSA/ECB/PKCS1Padding")` (no explicit OAEP)

## Remediation Steps

- Replace `Cipher.getInstance("RSA")` with `Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")`
- Create OAEPParameterSpec with SHA-256, MGF1ParameterSpec.SHA256, and PSource.PSpecified.DEFAULT
- Initialize cipher with the OAEP parameter spec using `cipher.init()` with AlgorithmParameterSpec
- Generate RSA keys with `KeyPairGenerator` at 3072-bit for new keys, not the 2048-bit floor alone
- Test encryption/decryption with sample data to verify proper OAEP implementation
