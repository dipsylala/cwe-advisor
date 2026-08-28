# CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Request/Response Splitting') - Java

## LLM Guidance

HTTP Response Splitting occurs when attackers inject CRLF characters (`\r\n`) into HTTP headers, enabling them to inject additional headers or response bodies, leading to cache poisoning, XSS, or session hijacking. Use Spring Framework's built-in redirect methods and header builders that automatically sanitize inputs; never manually construct headers with untrusted data.

## Key Principles

- Use framework-provided abstractions: Spring's `redirect:` prefix, `RedirectView`, `ResponseCookie.from()`, and `ContentDisposition.builder()` handle encoding automatically
- Validate and sanitize user input: Reject CRLF sequences (`\r`, `\n`) and Unicode line terminators (U+0085 NEL, U+2028 LINE SEPARATOR, U+2029 PARAGRAPH SEPARATOR) from any data used in headers
- Apply allowlisting: Restrict header values to expected character sets (alphanumeric, safe punctuation)
- Avoid manual header construction: Never concatenate user input directly into headers
- Use safe APIs: Prefer `UriComponentsBuilder` for URL construction with proper encoding
- Build a `Content-Disposition` with the framework's builder (`ContentDisposition.builder(...).filename(name, UTF_8)`), which emits the RFC 5987 form, rather than interpolating a filename into the header string
- `response.getContentType()` returns the value the application set, not the value the container will write - Tomcat and Jetty replace CR and LF with a space at write time, so a value read back still contains the payload and nothing is logged
- `URLEncoder.encode()` is form encoding, not header encoding: it turns a space into `+`, so it is the wrong tool for a header parameter even though it removes the newline
- Validate a redirect target as a path against an allowlist rather than checking `startsWith("/")`, which accepts `//evil.example` as a protocol-relative URL

## Taint Sinks

`response.setHeader()`, `response.addHeader()`, `response.sendRedirect()`

## Remediation Steps

- Replace manual `response.setHeader()` calls with Spring's `ResponseCookie.from()` builder for cookies
- Use `redirect:` prefix in controller return values instead of manually setting `Location` headers
- Apply input validation to reject `\r`, `\n`, `\u0085`, `\u2028`, and `\u2029` characters before any header operations; also strip percent-encoded variants (`%0d`, `%0a`)
- Use `ContentDisposition.builder()` for file download headers instead of string concatenation
- Implement allowlist validation for redirect URLs using parsed local paths or strict regex patterns that reject `//`
- Review all response header manipulations and replace with framework methods
