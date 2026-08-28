# CWE-780: Use of RSA Algorithm without OAEP - Java

## LLM Guidance

Using RSA encryption without OAEP (Optimal Asymmetric Encryption Padding) enables padding oracle attacks, chosen ciphertext attacks, and message malleability. In Java, this commonly occurs when using `Cipher.getInstance("RSA")` without specifying the padding mode, which defaults to the insecure PKCS#1 v1.5 padding. Always use `Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")` with explicit OAEP parameters.

## Key Principles

- Always specify the complete cipher transformation string including OAEP padding mode
- Use SHA-256 or stronger hash functions for OAEP (avoid SHA-1)
- Configure OAEPParameterSpec explicitly with MGF1 and appropriate hash algorithm
- Use RSA key sizes of 2048 bits minimum (4096 recommended for sensitive data)
- Do not report the difference: `BadPaddingException` and `IllegalBlockSizeException` distinguish "padding parsed" from "it did not", which is exactly the oracle the attack needs - catch both, return one generic failure, and log the detail server-side

## Taint Sinks

`Cipher.getInstance("RSA")`, `Cipher.getInstance("RSA/ECB/PKCS1Padding")` (no explicit OAEP)

## Remediation Steps

- Replace `Cipher.getInstance("RSA")` with `Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")`
- Create OAEPParameterSpec with SHA-256, MGF1ParameterSpec.SHA256, and PSource.PSpecified.DEFAULT
- Initialize cipher with the OAEP parameter spec using `cipher.init()` with AlgorithmParameterSpec
- Generate RSA keys with minimum 2048-bit key size using KeyPairGenerator
- Test encryption/decryption with sample data to verify proper OAEP implementation
