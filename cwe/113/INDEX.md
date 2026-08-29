# CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Request/Response Splitting')

## LLM Guidance

HTTP Response Splitting occurs when untrusted user input is included in HTTP headers without proper validation or encoding, allowing attackers to inject CRLF characters (carriage return and line feed). This enables attackers to create additional headers or inject complete HTTP responses, potentially leading to cache poisoning, XSS, or session hijacking.

## Key Principles

- Never allow untrusted input to directly influence HTTP response headers, and never derive a header *name* from input - name checking is the part frameworks disagree about most: Django runs the same CR/LF check over the key, while Werkzeug's `Headers` documents its keys as "assumed to be trusted" and checks only values
- Reject rather than strip: removing the newlines from `/account\r\nSet-Cookie: admin=true` yields `/accountSet-Cookie: admin=true`, a redirect target nobody chose, emitted with a 302 and indistinguishable from a normal request in the log. Decide what the value is allowed to *be* - an allowlist of the characters legal in that header's grammar - rather than enumerating characters to remove, since the list moves (`"`/`;` inside a quoted `Content-Disposition` parameter needs no newline at all)
- Use framework-provided header-setting functions that auto-sanitize - `redirect()`, the cookie builders (`set_cookie()`, `ResponseCookie.from()`), a content-disposition builder - rather than assembling a header line; a hand-built `Set-Cookie` also silently drops `HttpOnly`, `Secure` and `SameSite`
- The framework's check lives in its header object, so a raw WSGI/ASGI response, a proxy shim, a caching or logging layer that rebuilds headers, or bytes written straight to the socket does not have it
- A CRLF filter does not fix an open redirect: `https://evil.example` is a legal header value. Validate a redirect destination against an allowlist (or as a relative path from a known character class), which covers both weaknesses in one check
- Do not chase the Unicode line terminators as a splitting vector. Only a CR or LF *octet* splits a response, and U+0085, U+2028 and U+2029 do not become one: Tomcat and Jetty cannot emit a code point above 0xFF at all, and U+0085 leaves as the single byte 0x85, which no HTTP parser treats as a line break. They matter for log injection and for downstream parsers, not here

## Remediation Steps

- Trace to sinks. Find where untrusted data reaches an HTTP response header (Location, Set-Cookie, custom headers), and check every header-setting call site rather than only the one the scanner named
- Check the value the header will actually receive. A framework has usually already percent-decoded a query parameter, so `%0d%0a` in the request arrives as literal CR LF - which means a filter that removes the three-character string `%0d` protects nothing and corrupts any legitimate value containing it. The case that is real is a *second* decode downstream, where `%250d%250a` survives your check as text and a proxy or another framework layer turns it into a raw CRLF afterwards. That decode is the sink to fix
- Validate header values against a whole-string match, not a search, and anchor at the true end of the string - `$` also matches before a trailing newline in Python, .NET and PCRE, so `^...$` admits the character being excluded. The correct spelling differs per language and is not portable; see the language entry
- Where the value genuinely cannot be reduced to a character class (a filename in another script, a free-text note), encode it using the header's own grammar - RFC 5987 `filename*=UTF-8''...` - rather than filtering, since encoding is reversible and filtering silently substitutes a different value
- Reject with a 4xx: a passing scan is not a fix, because the platforms differ. Tomcat and Jetty replace every C0 control character except TAB with a space as the header is written (silently, and `getContentType()` still returns the original), PHP drops a header whose value contains CR or LF mid-string - while silently trimming one that only trails, so that header is still sent - and ASP.NET Core, Node, Flask and Django raise, which is a 500 any client can trigger at will
