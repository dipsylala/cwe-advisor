# CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute

## LLM Guidance

Without the flag the browser sends the cookie over cleartext HTTP whenever it is given the chance, which is why a redirect to HTTPS and HSTS do not substitute for it - both act after the first request has gone. The general cleartext-transmission finding is CWE-319.

## Key Principles

- Never allow sensitive cookies to be transmitted over unencrypted connections
- Cookie confidentiality must be enforced by transport layer (HTTPS) and server configuration
- The `Secure` flag is mandatory for any cookie containing authentication or session data
- Client behavior cannot be trusted; server-side enforcement is required
- Consider a `__Host-` or `__Secure-` name prefix so the browser rejects the cookie when `Secure` is missing, making a deployment that loses the flag fail visibly rather than issuing a plaintext cookie - but apply it only after confirming the flag reaches the wire, since the browser silently discards a prefixed cookie without it and that presents as a login loop
- Unlike `Secure`, the stricter `SameSite` value is not simply the safer one: choose `Strict` or `Lax` per flow, since `Strict` withholds the cookie from inbound links and SSO or OAuth callbacks
- Apply the flag to every sensitive cookie - session, auth token, CSRF token, remember-me - not only the session id

## Remediation Steps

- Review flaw details to identify all cookies lacking the `Secure` flag
- Locate cookie-setting code in authentication and session management modules
- Set the `Secure` attribute on every cookie that carries session or authentication data
- Use the framework's cookie-attribute setting to mark the cookie secure (see the language-specific guidance for exact syntax)
- Verify HTTPS is enforced site-wide; the `Secure` flag requires HTTPS to function
- Test in production-like environment to confirm cookies are not sent over HTTP
