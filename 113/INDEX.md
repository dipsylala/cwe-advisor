# CWE-113: HTTP Response Splitting

## LLM Guidance

HTTP Response Splitting occurs when untrusted user input is included in HTTP headers without proper validation or encoding, allowing attackers to inject CRLF characters (carriage return and line feed). This enables attackers to create additional headers or inject complete HTTP responses, potentially leading to cache poisoning, XSS, or session hijacking.

## Key Principles

- Never allow untrusted input to directly influence HTTP response headers
- Header values must be validated or sanitized by the server to prevent CRLF injection
- Construct headers server-side rather than incorporating external data
- Block or encode CR (`\r`, U+000D) and LF (`\n`, U+000A) in all header values — also strip Unicode line terminators that some HTTP parsers treat equivalently: U+0085 (NEL), U+2028 (LINE SEPARATOR), and U+2029 (PARAGRAPH SEPARATOR)
- Use framework-provided header-setting functions that auto-sanitize

## Remediation Steps

- Identify sources. Locate where untrusted data enters (HTTP parameters, cookies, database, external APIs)
- Trace to sinks. Find where data is set in HTTP response headers (Location, Set-Cookie, custom headers)
- Review data flow. Check each step in the data path for missing sanitization
- Remove CRLF and Unicode line terminators. Strip or encode `\r` (U+000D), `\n` (U+000A), U+0085 (NEL), U+2028 (LINE SEPARATOR), and U+2029 (PARAGRAPH SEPARATOR) from all untrusted input before header insertion
- Use safe APIs. Leverage framework functions that automatically prevent header injection
- Validate header values. Ensure values match expected format before setting headers
