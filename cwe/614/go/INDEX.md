# CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute - Go

## LLM Guidance

Go's `net/http.Cookie` struct sets no security attributes by default, so `http.SetCookie()` calls that omit `Secure`, `HttpOnly`, and `SameSite` silently produce a cookie that can be sent over plain HTTP and read by client-side scripts. Locate every `http.Cookie` literal and session-library options struct (e.g. `gorilla/sessions.Options`) and set `Secure: true`, `HttpOnly: true`, and an explicit `SameSite` mode. Skip `Secure` only for cookies used purely in local, plain-HTTP development; never in code paths that also run in production.

## Key Principles

- Set `Secure: true` on every `http.Cookie` carrying a session ID, auth token, or other sensitive data
- Set `HttpOnly: true` alongside `Secure` to block JavaScript access via `document.cookie` (XSS mitigation)
- Set `SameSite` explicitly (`http.SameSiteStrictMode` or `http.SameSiteLaxMode`) - do not leave it unset and rely on browser defaults
- Each `http.Cookie` and each session-library `Options` struct is independent - a library like `gorilla/sessions` has its own `Options` that must be configured separately from any handler-level `http.SetCookie` calls
- Do not derive `Secure` from `r.TLS != nil` when the app sits behind a reverse proxy - `r.TLS` reflects the proxy-to-app hop, which is often plaintext even when the client used HTTPS
- Keep `MaxAge` short for session cookies; use a separate, rotated token for "remember me" functionality
- Leave `Domain` unset unless a subdomain genuinely needs the cookie: setting it widens the cookie to every host under that domain, including one an attacker may control
- Deciding "is this HTTPS" from `r.RemoteAddr` or a forwarded header trusts the proxy chain - set `Secure` unconditionally and terminate TLS in front, rather than making the flag conditional

## Taint Sinks

`http.SetCookie()`, `http.Cookie{}` literal without `Secure: true`, `gorilla/sessions.Options` without `Secure: true`

## Remediation Steps

- Locate - Find every `net/http.Cookie{}` literal, `http.SetCookie()` call, and session-library options struct (e.g. `gorilla/sessions.Options`)
- Trace data flow - Confirm which cookies carry session IDs, auth tokens, or other sensitive values versus purely functional, non-sensitive cookies
- Replace the unsafe pattern - Add `Secure: true`, `HttpOnly: true`, and `SameSite: http.SameSiteStrictMode` (or `LaxMode`) to each sensitive cookie
- Harden configuration - If behind a reverse proxy, set `Secure` unconditionally rather than from `r.TLS`, and ensure the proxy forwards `X-Forwarded-Proto` if app logic needs to detect HTTPS
- Test - Inspect `Set-Cookie` response headers (browser devtools or `curl -v`) against the deployed HTTPS endpoint to confirm all three attributes are present
