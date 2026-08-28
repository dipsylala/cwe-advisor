# CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Request/Response Splitting')

## LLM Guidance

HTTP Response Splitting occurs when untrusted user input is included in HTTP headers without proper validation or encoding, allowing attackers to inject CRLF characters (carriage return and line feed). This enables attackers to create additional headers or inject complete HTTP responses, potentially leading to cache poisoning, XSS, or session hijacking.

## Key Principles

- Never allow untrusted input to directly influence HTTP response headers, and never derive a header *name* from input - name checking is the part frameworks disagree about most (Werkzeug does not check names at all)
- Header values must be validated or sanitized by the server to prevent CRLF injection
- Construct headers server-side rather than incorporating external data
- Reject rather than strip: removing the newlines from `/account\r\nSet-Cookie: admin=true` yields `/accountSet-Cookie: admin=true`, a redirect target nobody chose, emitted with a 302 and indistinguishable from a normal request in the log. Decide what the value is allowed to *be* - an allowlist of the characters legal in that header's grammar - rather than enumerating characters to remove, since the list moves (U+0085 NEL, U+2028, U+2029, and `"`/`;` inside a quoted `Content-Disposition` parameter, none of which needs a newline)
- Use framework-provided header-setting functions that auto-sanitize - `redirect()`, the cookie builders (`set_cookie()`, `ResponseCookie.from()`), a content-disposition builder - rather than assembling a header line; a hand-built `Set-Cookie` also silently drops `HttpOnly`, `Secure` and `SameSite`
- The framework's check lives in its header object, so a raw WSGI/ASGI response, a proxy shim, a caching or logging layer that rebuilds headers, or bytes written straight to the socket does not have it
- A CRLF filter does not fix an open redirect: `https://evil.example` is a legal header value. Validate a redirect destination against an allowlist (or as a relative path from a known character class), which covers both weaknesses in one check

## Remediation Steps

- Identify sources. Locate where untrusted data enters (HTTP parameters, cookies, database, external APIs)
- Trace to sinks. Find where data is set in HTTP response headers (Location, Set-Cookie, custom headers)
- Review data flow. Check each step in the data path for missing sanitization
- Remove CRLF and Unicode line terminators. Strip or encode `\r` (U+000D), `\n` (U+000A), U+0085 (NEL), U+2028 (LINE SEPARATOR), and U+2029 (PARAGRAPH SEPARATOR) from all untrusted input before header insertion
- Use safe APIs. Prefer framework functions that automatically prevent header injection
- Validate header values against a whole-string match, not a search, and anchor at the true end of the string: `$` also matches before a trailing newline in Python, .NET and PCRE, so `^...$` admits the character being excluded. Use `re.fullmatch()` in Python (where `\z` is not a valid escape before 3.14 and the strict anchor is the capital `\Z`), `\z` in .NET and Java, and `\z` or the `D` modifier in PHP
- Where the value genuinely cannot be reduced to a character class (a filename in another script, a free-text note), encode it using the header's own grammar - RFC 5987 `filename*=UTF-8''...` - rather than filtering, since encoding is reversible and filtering silently substitutes a different value
- Reject with a 4xx: a passing scan is not a fix, because the platforms differ. Tomcat and Jetty replace each CR and LF with a space as the header is written (silently, and `getContentType()` still returns the original), PHP drops the header entirely so the redirect never happens, and ASP.NET Core, Node, Flask and Django raise - a 500 any client can trigger at will
