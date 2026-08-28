# CWE-345: Insufficient Verification of Data Authenticity

## LLM Guidance

Insufficient verification of data authenticity occurs when applications don't validate that data hasn't been tampered with during storage or transmission. This includes accepting unsigned data, not verifying signatures/MACs, or trusting unauthenticated sources, enabling data tampering, message forgery, and MITM attacks.

## Key Principles

- Never allow untrusted data to influence security or control decisions unless its authenticity is verified by a server-controlled integrity mechanism
- Use cryptographic signatures or MACs to verify data has not been modified
- Validate data authenticity at trust boundaries before processing
- Implement server-side verification; never rely solely on client-side checks
- Apply defence-in-depth with multiple verification layers for critical data
- Bind freshness into the authenticated bytes: a valid MAC or signature never expires, so a captured genuine message replays forever. Put a nonce, monotonic sequence number, or timestamp *inside* the region the tag covers and reject anything already seen or outside the window - a timestamp carried alongside the tag is attacker-controlled and worthless
- Verify before use, not after: the MAC or signature check gates whether the data is parsed at all, not whether the result is trusted afterwards
- For new signature designs prefer RSA-PSS over PKCS#1 v1.5 and size new RSA keys at 3072 bits; Ed25519 and P-256 are the modern defaults

## Remediation Steps

- Review flaw details to identify files, line numbers, and code patterns where data authenticity verification is missing
- Identify what data lacks authentication - cookies, tokens, API messages, file uploads, database records, or configuration data
- Determine the data source and trace the flow to understand where unauthenticated data is accepted and used
- Implement HMAC-SHA256 or similar message authentication codes for verifying data integrity
- Add cryptographic signature verification for critical operations and data exchanges
- Validate all signatures/MACs server-side before trusting or processing the data
