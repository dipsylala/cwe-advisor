# CWE-780: Use of RSA Without OAEP - JavaScript/Node.js

## LLM Guidance

RSA encryption without OAEP (Optimal Asymmetric Encryption Padding) is vulnerable to padding oracle attacks and chosen ciphertext attacks. Audit explicit uses of `RSA_PKCS1_PADDING` and configure OAEP with SHA-256 or stronger; Node's OAEP defaults may use SHA-1 unless `oaepHash` is set.

## Key Principles

- Always specify `crypto.constants.RSA_PKCS1_OAEP_PADDING` when encrypting/decrypting with RSA
- Use minimum 2048-bit RSA keys (4096-bit recommended for long-term security)
- Prefer modern alternatives like AES-GCM with RSA-OAEP for hybrid encryption
- Never use legacy PKCS#1 v1.5 padding (`RSA_PKCS1_PADDING`) for encryption
- Consider using `publicEncrypt`/`privateDecrypt` with explicit padding configuration

## Remediation Steps

- Locate all `crypto.publicEncrypt()` and `crypto.privateDecrypt()` calls
- Add explicit `padding: crypto.constants.RSA_PKCS1_OAEP_PADDING` and `oaepHash: 'sha256'` to options
- Verify RSA key size is at least 2048 bits
- Test encryption/decryption with OAEP padding enabled
- Review and update all RSA encryption configurations
- Regenerate any data encrypted with PKCS#1 v1.5 padding

## Safe Pattern

```javascript
const crypto = require('crypto');

// Encrypt with OAEP
const encrypted = crypto.publicEncrypt(
  {
    key: publicKey,
    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: 'sha256'
  },
  Buffer.from('sensitive data')
);

// Decrypt with OAEP
const decrypted = crypto.privateDecrypt(
  {
    key: privateKey,
    padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
    oaepHash: 'sha256'
  },
  encrypted
);
```
