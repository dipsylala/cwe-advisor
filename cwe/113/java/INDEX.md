# CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Request/Response Splitting') - Java

## LLM Guidance

HTTP Response Splitting occurs when attackers inject CRLF characters (`\r\n`) into HTTP headers, enabling them to inject additional headers or response bodies, leading to cache poisoning, XSS, or session hijacking. The Servlet API itself promises nothing here - `setHeader`'s javadoc says nothing about CR, LF or validation, and the specification imposes no obligation on the container - so what protects the response is whichever container or filter is in front of it, and the redirect target is not protected at all.

## Key Principles

- **Spring Security already covers this response-side, if it is on the classpath.** `StrictHttpFirewall` wraps the response in `FirewalledResponse`, which checks `setHeader`, `addHeader`, `sendRedirect` and `addCookie` for CR and LF in both the name and the value, and throws rather than editing. That is the framework-level fix; per-call validation is what you write when it is absent
- Tomcat and Jetty both neutralise on the way out, but more broadly than CR/LF: each replaces every C0 control character except TAB with a space as the header is written, and the asymmetry past that matters: Tomcat also filters DEL (0x7F) while Jetty does not, and Jetty also replaces any code point above 0xFF. Jetty uses `.` rather than a space inside header *names*. It is silent, nothing is logged, and `response.getContentType()` returns the value the application set, not the value the container wrote
- Because a code point above 0xFF cannot survive that, U+2028 and U+2029 cannot split a response on either container, and U+0085 leaves as the byte 0x85, which is not a line terminator to an HTTP parser. Validate for the grammar you want, not for a list of Unicode terminators
- `ResponseCookie.from()` does not encode - it **validates and throws** `IllegalArgumentException` for a control character in the name or value, and it does so at `.build()`, not at `.from()`. Treat it as a reject, and catch it
- **The `redirect:` prefix and `RedirectView` do not sanitize the target either.** `RedirectView.sendRedirect` calls `response.setHeader("Location", ...)` - one of this entry's own sinks - and `encodeRedirectURL` is session-id rewriting, not CRLF encoding. Two open-redirect CVEs land here: CVE-2026-41844 (a `/**` mapping with no explicit view name) and CVE-2026-47887 (`UrlFileNameViewController`). On 7.0.x the OSS floor is **7.0.9**, which carries both - 41844 alone landed in 7.0.8. On 6.2.x, **6.2.19** closes 41844 but 47887's fix there is Enterprise-only, so that line has no OSS release covering both; 6.1.x, 6.0.x, 5.3.x and 5.2.x have none for either. Upgrading within those lines is not a fix
- `UriComponentsBuilder` does not encode on its own; the documented workflow makes `encode()` a separate step. It also has a three-round CVE history against exactly the pattern of parsing an external URL and then validating its host - CVE-2024-22243, then CVE-2024-22259 bypassing that fix, then CVE-2024-22262 bypassing that. Operative floors: **6.1.6 / 6.0.19 / 5.3.34**
- Build a `Content-Disposition` with `ContentDisposition.builder(...).filename(name, UTF_8)`, which emits an ASCII `filename` plus the RFC 5987 `filename*`. Note it *deletes* CR and LF from the filename rather than rejecting it, so like the container's space substitution it leaves the endpoint answering 200 with a value nobody chose - `ResponseCookie.from()` is the one to model, because it throws instead of repairing. `URLEncoder.encode()` is form encoding, not header encoding - it turns a space into `+` - so it is the wrong tool even though it removes the newline
- Validate a redirect target as a path against an allowlist rather than checking `startsWith("/")`. The Servlet specification is explicit that a location "relative with two leading '/'" is interpreted as a network-path reference, so `//evil.example` is an off-site redirect by the spec's own rules

## Taint Sinks

`response.setHeader()`, `response.addHeader()`, `response.sendRedirect()`, `response.addCookie()`

## Remediation Steps

- Check whether a Spring Security filter chain is present; if so, `FirewalledResponse` already rejects CR/LF on every sink above and the finding may be a false positive worth recording with that reason
- Replace manual `response.setHeader()` calls with Spring's `ResponseCookie.from()` builder for cookies, catching the `IllegalArgumentException` it throws on a bad value
- Use the `redirect:` prefix for the redirect mechanism, but validate the destination separately against an allowlist - the prefix does nothing for an off-site target, and check the Spring version against the floors above
- Validate header values against an allowlist of the characters that header's grammar permits, anchored with `\z` and `Matcher.matches()`, and reject rather than edit. Do not filter percent-encoded forms: in a header value `%0d` is three literal characters that cannot split a response, and removing that sequence corrupts legitimate values
- Use `ContentDisposition.builder()` for file download headers instead of string concatenation
- Assert on the *emitted* header value rather than on the absence of an extra header. On Tomcat and Jetty the payload produces no exception, no 500 and no log line, so a test that only looks for an injected header passes against the unfixed code
- Review all response header manipulations and replace with framework methods
