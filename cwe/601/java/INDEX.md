# CWE-601: URL Redirection to Untrusted Site ('Open Redirect') - Java

## LLM Guidance

Open redirect vulnerabilities in Java web applications occur when user-controlled input is used in `sendRedirect()` or `<meta>` refresh tags without proper validation, enabling phishing attacks and credential theft. `RequestDispatcher.forward()` is not a sink for this CWE: the Servlet spec scopes it to a resource on the server, and it never sends a `Location` header or otherwise reaches the client's browser. The core fix is to validate redirect URLs against an allowlist of trusted destinations or use relative paths only. For Spring MVC and Jakarta EE applications, use path-based routing instead of accepting arbitrary URLs.

## Key Principles

- Allowlist validation: Match redirect URLs against a predefined list of permitted domains or paths
- Relative paths only: Use context-relative paths (`/dashboard`) instead of accepting full URLs
- Avoid user input in redirects: Use indirect references (e.g., enums, IDs mapped to destinations)
- Strict URL parsing: Validate protocol, domain, and path components before redirecting
- Framework-level guards: Configure Spring Security or servlet filters to block external redirects
- Decide on the parsed URI, not the string, but branch on `getHost()`, not `isAbsolute()`: a scheme-relative value like `//evil.example` is not absolute (no scheme) yet has a non-null host, and an opaque URI like `javascript:alert(1)` is absolute yet has a null host, so `isAbsolute()` alone misclassifies both. Treat a non-null host as needing an allowlist match, and reject an absolute URI whose host is null outright rather than letting it fall through as safe
- A `startsWith("/")` check accepts `//evil.example`, which the browser reads as protocol-relative - test for it directly with the host check above. A leading backslash (`/\evil.example`) is a browser-side bypass, not a Java one: `URI.create` throws `IllegalArgumentException` on an unencoded backslash rather than treating it as a separator, so a value that fails to parse must be rejected, not passed through to a default-safe branch
- Reject `javascript:` and `data:` schemes explicitly where the value can reach an anchor rather than a `Location` header
- Where a framework offers its own `isLocalUrl()`-style predicate, use it rather than reimplementing the check, and confirm what it does with a backslash and with an encoded separator

## Taint Sinks

`response.sendRedirect()`, `"redirect:" + userInput`, `<meta http-equiv="refresh">` with unvalidated URLs

## Remediation Steps

- Identify all `response.sendRedirect()`, `return "redirect -"`, and `<meta http-equiv="refresh">` usage
- Replace user-controlled URLs with enum/ID mapping to predefined destinations
- For necessary external redirects, validate against an allowlist of trusted domains
- Use `URI` class to parse and validate URL components (scheme, host, path)
- Implement a centralized redirect validator for consistent enforcement, falling back to a fixed safe path when validation fails or `URI.create` throws `IllegalArgumentException` (it wraps the checked `URISyntaxException`, so catch the unchecked form)
- Add unit tests verifying that malicious URLs (`//evil.com`, `https://attacker.com`) are rejected
