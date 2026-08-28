# CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Request/Response Splitting') - JavaScript

## LLM Guidance

HTTP Response Splitting in Node.js occurs when user-supplied values are passed to `res.setHeader()`, `res.redirect()`, or `res.cookie()` without stripping CRLF characters (`\r\n`). An attacker who can inject a newline into a `Location` or `Set-Cookie` header can append a complete second HTTP response, enabling cache poisoning, XSS, and session hijacking. Since the CVE-2016-2216 fix (Node 4.4.4/6.2.1), the `http` module rejects a raw CR or LF in a header value, which blocks the classic literal-newline attack in `res.setHeader()`/`res.writeHead()`; Express delegates to it. The specific `ERR_INVALID_CHAR` error code is a later addition (Node's error-code codification around v9-v10) but the underlying rejection is not. This does not cover percent-encoded variants (`%0d`, `%0a`) reaching headers after URL-decoding, Unicode line separators, or values injected through libraries with their own header/cookie serialization. Sanitize all user input before it reaches any header-setting call, or use framework redirect helpers that encode values automatically.

## Key Principles

- Strip or reject `\r` (U+000D), `\n` (U+000A), and their percent-encoded forms (`%0d`, `%0a`) from any user input placed in headers
- Also strip Unicode line terminators: U+0085 (NEL), U+2028 (LINE SEPARATOR), U+2029 (PARAGRAPH SEPARATOR)
- Use `res.redirect()` with a validated, allowlisted URL rather than `res.setHeader('Location', userInput)`
- Validate redirect targets against an allowlist of known-safe paths or origins before redirecting
- Avoid manually constructing `Set-Cookie` header values - use `res.cookie()` with `httpOnly` and `sameSite` options
- Node rejects a bad header *name* with `ERR_INVALID_HTTP_TOKEN` and a bad value with `ERR_INVALID_CHAR`, so both surface as a 500 rather than a split response - fix the validation instead of relying on the throw, and note neither applies to bytes written directly to the socket
- Use the framework's cookie API rather than composing a `Set-Cookie` string: a hand-built one silently loses `Secure`, `HttpOnly` and `SameSite` along with the escaping
- `res.setHeader('Location', url)` takes a destination value - validate it against an allowlist, since rejecting control characters says nothing about where the redirect points

## Taint Sinks

`res.setHeader()`, `res.writeHead()`, `res.redirect()`, `res.cookie()`

## Remediation Steps

- Replace manual `res.setHeader('Location', userInput)` with `res.redirect()` after URL validation
- Validate redirect URLs against an allowlist or confirm they are local paths matching `/(?!/)[a-zA-Z0-9/_-]+`
- Strip CRLF and Unicode line terminators from any string before passing it to `res.setHeader()` or `res.cookie()`; also strip percent-encoded variants `%0d` and `%0a`
- For `Content-Disposition` (file downloads), use a fixed filename or encode it with `encodeURIComponent()` rather than interpolating user input directly
- Use `res.cookie('name', value, { httpOnly: true, sameSite: 'strict' })` instead of setting `Set-Cookie` manually
- Test by submitting `%0d%0aInjected-Header: evil` in redirect/cookie parameters and confirm the injected header does not appear
