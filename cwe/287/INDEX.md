# CWE-287: Improper Authentication

## LLM Guidance

Improper authentication occurs when an application fails to correctly verify user, service, or system identity through flawed authentication logic itself - not just weak credentials. Common real-world bypass classes include JWT algorithm-confusion or `alg: none` acceptance, weak or guessable JWT signing secrets, OAuth/OIDC flows that omit or fail to validate the `state` parameter, and password-reset tokens that are not bound to the account that requested them. The core fix is never trusting client-supplied identity and requiring server-validated authentication for every request.

## Key Principles

- Never trust client-supplied identity claims - always validate server-side
- Implement complete authentication checks before accepting any session or identity
- Use defence-in-depth with multiple authentication factors
- Enforce authentication uniformly across all protected resources
- Properly manage session lifecycle (generation, timeout, invalidation)
- Regenerate the session identifier after a successful login, so a value the attacker planted beforehand cannot become an authenticated session
- Fail closed with `401` on a missing, malformed, expired, or invalid credential rather than falling through to an anonymous path, and send the `WWW-Authenticate` challenge header that a 401 requires - a denial for a caller who is authenticated but not permitted is `403` instead
- In any lookup-then-verify flow - login, reset-token redemption, API key or TOTP checks - do the same work when the record is missing: verify the submitted credential against a dummy hash and discard the result, so response time cannot answer which accounts exist
- Produce that dummy with the application's own hasher at its configured parameters; an empty or malformed placeholder fails the format check in microseconds and leaves the gap open, as does a stored hash left empty for SSO-only accounts
- Do not assume the framework closes that gap - some hash on the unknown-user branch and some do not; confirm it for the one in use
- Validate every part of a token, not just its signature: issuer, audience, expiry, and revocation status
- Route to the specific descendant where the finding names one: no identity check on the path at all is CWE-306, certificate validation is CWE-295, unrestricted authentication attempts is CWE-307, weak password requirements CWE-521, weak recovery CWE-640, hard-coded credentials CWE-798, and insufficiently protected credentials CWE-522

## Remediation Steps

- Identify all authentication entry points (login forms, API auth, SSO, OAuth, password reset)
- Examine credential validation logic for bypass conditions or incomplete checks
- For token-based auth, verify the signing algorithm is pinned server-side (reject `alg: none` and algorithm-confusion attacks) and the signing secret/key has sufficient entropy
- For OAuth/OIDC flows, confirm the `state` parameter is generated, stored, and validated on callback to prevent CSRF-into-login
- For password-reset flows, confirm the reset token is bound to the account that requested it and cannot be replayed against a different account
- Review session token generation, storage, timeout, and invalidation mechanisms
- Audit all endpoints to ensure authentication is required before access
- Find and protect resources lacking authentication checks, especially admin functions and APIs
- Time a wrong password against an unknown username; a sub-millisecond answer for the unknown username is a user-enumeration oracle that no re-scan detects
