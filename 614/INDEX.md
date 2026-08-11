# CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute

## LLM Guidance

Sensitive cookies (session IDs, authentication tokens) transmitted without the `Secure` flag can be intercepted over unencrypted HTTP connections, exposing them to attackers. The fix requires setting the `Secure` flag on all sensitive cookies to ensure they are only transmitted over HTTPS connections.

## Key Principles

- Never allow sensitive cookies to be transmitted over unencrypted connections
- Cookie confidentiality must be enforced by transport layer (HTTPS) and server configuration
- The `Secure` flag is mandatory for any cookie containing authentication or session data
- Client behavior cannot be trusted; server-side enforcement is required

## Remediation Steps

- Review flaw details to identify all cookies lacking the `Secure` flag
- Locate cookie-setting code in authentication and session management modules
- Set the `Secure` attribute on every cookie that carries session or authentication data
- Use the framework's cookie-attribute setting to mark the cookie secure (see the language-specific guidance for exact syntax)
- Verify HTTPS is enforced site-wide; the `Secure` flag requires HTTPS to function
- Test in production-like environment to confirm cookies are not sent over HTTP
