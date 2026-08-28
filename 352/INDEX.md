# CWE-352: Cross-Site Request Forgery (CSRF)

## LLM Guidance

CSRF attacks force authenticated users to perform unwanted actions by exploiting the website's trust in the user's browser. Attackers craft malicious requests that abuse the victim's active session to execute state-changing operations. The core fix is verifying request origin and authenticity using server-controlled CSRF tokens.

## Key Principles

- Never process authenticated state-changing requests without verifying origin and authenticity
- Require server-controlled validation mechanisms (tokens) for all POST, PUT, DELETE operations
- Do not rely solely on session cookies for authentication of state-changing actions
- Validate CSRF tokens on the server side before processing any data modifications
- Use framework-provided CSRF protection rather than custom implementations
- Set `SameSite` on the session cookie as defence-in-depth alongside the token, not instead of it: it is a browser-enforced control that non-browser clients ignore, and `Strict` also withholds the cookie from inbound links, SSO redirects and OAuth callbacks
- Generate the token from a CSPRNG at 128 bits or more, bind it to the session, and compare it in constant time
- Protect every state-changing route, including ones that accept JSON or a custom content type - a preflight is not an authorization check, and an endpoint reachable with a simple request has none
- Re-issue the token when the session is regenerated at login, so the pre-authentication token cannot be replayed

## Remediation Steps

- Identify all state-changing endpoints (POST, PUT, DELETE) in security findings by file and line number
- Locate forms and AJAX requests that lack CSRF token inclusion
- Review framework configuration to ensure CSRF protection is enabled globally
- Implement Synchronizer Token Pattern with cryptographically random tokens (minimum 32 bytes)
- Include CSRF tokens in all forms and AJAX requests that modify data
- Validate tokens server-side before processing any state-changing request
