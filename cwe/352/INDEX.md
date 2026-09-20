# CWE-352: Cross-Site Request Forgery (CSRF)

## LLM Guidance

The fix verifies the request's origin or authenticity server-side. A session cookie arriving with the request is not evidence of intent, because the browser attaches it whoever caused the request to be sent.

## Key Principles

- Never process authenticated state-changing requests without verifying origin and authenticity
- Require server-controlled validation mechanisms (tokens) for all POST, PUT, DELETE operations
- Do not rely solely on session cookies for authentication of state-changing actions
- Validate CSRF tokens on the server side before processing any data modifications
- Use framework-provided CSRF protection rather than custom implementations
- Set `SameSite` on the session cookie as defence-in-depth alongside the token, not instead of it: it is a browser-enforced control that non-browser clients ignore, and `Strict` also withholds the cookie from inbound links, SSO redirects and OAuth callbacks
- Generate the token from a CSPRNG at 128 bits or more, bind it to the session, and compare it in constant time
- Protect every state-changing route, including ones that accept JSON or a custom content type - a preflight is not an authorization check, and an endpoint reachable with a simple request has none
- CSRF middleware validates only the non-safe methods, so a state change reachable by `GET` is unprotected even where protection is correctly enabled - `GET /account/delete?confirm=true` passes straight through the filter. The fix is to move the action to POST/DELETE, not to add a token to a GET route
- Before changing the verb, find out why the route is a GET. When it exists so that a link can trigger the action - an email button, a settings-page anchor, anything without a JavaScript-submitted form - keep a GET at that URL that renders a confirmation page whose form POSTs (with the token) to the state-changing route. Changing the method alone, or deleting the GET route, breaks every existing link to it, which is a silent behaviour change rather than a fix; say in the write-up which links now land on the confirmation page
- Re-issue the token when the session is regenerated at login, so the pre-authentication token cannot be replayed

## Remediation Steps

- Identify all state-changing endpoints (POST, PUT, DELETE) in security findings by file and line number, plus any GET route whose handler mutates state - those never reach the middleware at all
- Locate forms and AJAX requests that lack CSRF token inclusion
- Review framework configuration to ensure CSRF protection is enabled globally
- Implement Synchronizer Token Pattern with cryptographically random tokens of at least 128 bits
- Include CSRF tokens in all forms and AJAX requests that modify data
- Validate tokens server-side before processing any state-changing request
- Verify with three assertions rather than a status code: a forged cross-site request is
  rejected *and* left the record unchanged, a token minted in one session is rejected in
  another - the one test that catches a token generated well but never bound to a session -
  and every legitimate form and AJAX path still succeeds, which is what enabling protection
  breaks far more often than it fails to block an attack
