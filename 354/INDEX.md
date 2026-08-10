# CWE-354: Improper Validation of Integrity Check Value

## LLM Guidance

This weakness occurs when data such as files, messages, or tokens is accepted without verifying an integrity value, or the verification uses a non-cryptographic algorithm, or the check is computed but its result is ignored. The core fix is to verify a cryptographically strong integrity value (HMAC or digital signature, not a plain checksum or hash) before trusting or acting on the data, and to reject the data outright on mismatch.

## Key Principles

- Use a cryptographic MAC (HMAC) or digital signature for security-relevant integrity; checksums like CRC32 only detect accidental corruption, not tampering
- Always check the verification result and reject the data on failure - do not log and continue processing it
- Use a constant-time comparison for MAC or signature verification to avoid timing side-channels
- Keep the integrity key or signing key out of untrusted reach; never embed it in client-side code or transmit it alongside the data
- Verify integrity before parsing, decrypting, or otherwise acting on the data, not after
- When encryption is also used, verify integrity as part of an authenticated encryption mode or an encrypt-then-MAC construction, rather than layering unauthenticated encryption with a separate weak checksum

## Remediation Steps

- Locate - Find where external or stored data is read (file loads, API payloads, tokens, cached objects) and where an integrity value accompanies it
- Trace data flow - Follow the data and its integrity value from source to the point where they should be compared
- Identify the unsafe pattern - Missing verification call, verification result not checked, a weak algorithm used for security purposes, or a non-constant-time comparison
- Replace with the safe pattern - Compute and compare a strong MAC or signature using a maintained cryptography library, with a constant-time comparison
- Add secondary controls - Reject and log on failure, protect the integrity key's storage and distribution, and consider authenticated encryption for combined confidentiality and integrity
- Test - Tamper with the data or its integrity value and confirm rejection; confirm unmodified data with a correct value is accepted
