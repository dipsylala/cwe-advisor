# CWE-656: Reliance on Security Through Obscurity

## LLM Guidance

Security through obscurity relies on hiding implementation details (secret URLs, obfuscated code, unusual ports) instead of implementing proper security controls like authentication, encryption, and access control. This approach provides a false sense of security that fails once attackers discover the hidden information. Replace obscurity with real security controls that remain effective even when implementation details are known.

## Key Principles

- Use role-based access control and session management instead of hidden URLs or obfuscated endpoints
- Encryption is not encoding: replace base64, XOR, or custom encoding with proper cryptographic algorithms (AES, RSA)
- Move security checks from client-side obfuscation to server-side enforcement
- Layer multiple security controls (defence-in-depth) rather than relying on a single obscurity measure
- Test security assuming the attacker has already discovered all obscured information

## Remediation Steps

- Audit codebase for obscurity-based patterns (hidden endpoints, encoded credentials, client-side checks)
- Identify what's being protected by obscurity and assess its discoverability via brute-force, code analysis, or traffic inspection
- Replace hidden URLs with authenticated endpoints using proper access controls
- Convert encoded secrets to encrypted values using strong cryptographic libraries
- Move security logic from client-side to server-side with proper validation
- Test system security assuming attacker has full knowledge of obscured implementation details
