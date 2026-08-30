# CWE-601: URL Redirection to Untrusted Site ('Open Redirect') - JavaScript

## LLM Guidance

Server-side open redirects in Node.js occur when user-controlled input flows into `res.redirect()` or a `res.writeHead()` Location header without validation. Neither does any safety check on its own - `res.redirect()` only percent-encodes the value and resolves it against the current path, exactly like the sanitization every other language's HTTP framework does here. `window.location` assignment is a separate, client-side vector: it needs the same allowlist logic re-implemented in browser code, since none of the server-side steps below run there. The core fix is to validate redirect destinations against an allowlist of trusted domains or use relative paths only.

**Primary Defence:** Validate all redirect URLs against an allowlist of allowed domains or restrict to relative paths only.

## Key Principles

- Implement allowlist validation for all redirect destinations before redirecting
- Use relative paths instead of absolute URLs when possible
- Reject or sanitize any redirect URL containing external domains
- Apply URL parsing to verify protocol and hostname match expected values
- `res.redirect()` and `res.writeHead()`'s Location header perform no validation of scheme or host - only percent-encoding and relative-path resolution - so an unvalidated value reaches the client exactly as given
- Node's `URL` implements the WHATWG URL Standard, so unlike Go's `net/url` or Python's `urllib.parse`, it already normalizes a leading backslash the same way a browser does (`/\evil.com` resolves `hostname` to `evil.com`) - no separate backslash string-check is needed as long as the value is run through `new URL()` before any comparison

## Taint Sinks

`res.redirect()`, `res.writeHead()` Location header, `window.location` / `window.location.href` assignment (client-side; needs its own check, not the server-side steps below)

## Remediation Steps

- Parse with a fixed, trusted base so a relative value doesn't throw: `new URL(target, 'https://your-trusted-host.example')` - the bare `new URL(target)` form throws a `TypeError` on any input without its own scheme and host, which is the common case for a `next=`/`redirect=` parameter
- Compare `parsed.origin` against the request's own trusted origin for a same-site check, rather than testing `hostname` alone - `origin` folds in scheme and port, so a mismatched scheme (`javascript:`) or port can't slip through a hostname-only comparison
- Build that trusted origin from a fixed, server-configured value, not from `req.headers.host` - behind a proxy that forwards an unvalidated `Host` header, an attacker who controls the header controls both sides of the `origin === base` comparison
- For an intentionally external redirect, compare `parsed.hostname` against an explicit allowlist and require `parsed.protocol === 'https:'` (note the trailing colon - that's how the WHATWG URL API returns it)
- Reject invalid or non-matching destinations with an error or a fallback to a safe default page
- Log blocked redirect attempts for security monitoring
