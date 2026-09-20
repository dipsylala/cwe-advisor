# CWE-656: Reliance on Security Through Obscurity

## LLM Guidance

MITRE allows this Class with review for an unusual reason: it has no Base-level children, so there is often nothing narrower to file. Do the root-cause analysis first, and where nothing more specific fits, this is the right entry rather than a placeholder. The test is whether the control still holds once the mechanism is public.

## Key Principles

- Use role-based access control and session management instead of hidden URLs or obfuscated endpoints
- Encryption is not encoding: replace base64, XOR, or custom encoding with proper cryptographic algorithms (AES, RSA)
- Move security checks from client-side obfuscation to server-side enforcement
- Layer multiple security controls (defence-in-depth) rather than relying on a single obscurity measure
- Test security assuming the attacker has already discovered all obscured information
- Obscurity is legitimate only as a layer on top of a control that would hold without it - keeping version numbers out of headers reduces reconnaissance and is not a substitute for patching

## Remediation Steps

- Audit codebase for obscurity-based patterns (hidden endpoints, encoded credentials, client-side checks)
- Identify what's being protected by obscurity and assess its discoverability via brute-force, code analysis, or traffic inspection
- Replace hidden URLs with authenticated endpoints using proper access controls
- Convert encoded secrets to encrypted values using strong cryptographic libraries
- Move security logic from client-side to server-side with proper validation
- Test system security assuming attacker has full knowledge of obscured implementation details
