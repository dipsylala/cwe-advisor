# CWE-287: Improper Authentication

## LLM Guidance

Improper authentication occurs when an application fails to correctly verify user, service, or system identity through flawed authentication logic itself - not just weak credentials. These flaws allow attackers to bypass authentication entirely, impersonate legitimate users, or escalate privileges. Common real-world bypass classes include JWT algorithm-confusion or `alg: none` acceptance, weak or guessable JWT signing secrets, OAuth/OIDC flows that omit or fail to validate the `state` parameter, and password-reset tokens that are not bound to the account that requested them. The core fix is never trusting client-supplied identity and requiring server-validated authentication for every request.

## Key Principles

- Never trust client-supplied identity claims - always validate server-side
- Implement complete authentication checks before accepting any session or identity
- Use defence-in-depth with multiple authentication factors
- Enforce authentication uniformly across all protected resources
- Properly manage session lifecycle (generation, timeout, invalidation)

## Remediation Steps

- Identify all authentication entry points (login forms, API auth, SSO, OAuth, password reset)
- Examine credential validation logic for bypass conditions or incomplete checks
- For token-based auth, verify the signing algorithm is pinned server-side (reject `alg: none` and algorithm-confusion attacks) and the signing secret/key has sufficient entropy
- For OAuth/OIDC flows, confirm the `state` parameter is generated, stored, and validated on callback to prevent CSRF-into-login
- For password-reset flows, confirm the reset token is bound to the account that requested it and cannot be replayed against a different account
- Review session token generation, storage, timeout, and invalidation mechanisms
- Audit all endpoints to ensure authentication is required before access
- Find and protect resources lacking authentication checks, especially admin functions and APIs
- Implement multi-factor authentication for sensitive operations
