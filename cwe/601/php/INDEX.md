# CWE-601: URL Redirection to Untrusted Site ('Open Redirect') - PHP

## LLM Guidance

Open redirect vulnerabilities occur when user-controlled input is used in `header("Location: ...")`, `<meta>` refresh tags, or JavaScript redirects without validation, enabling phishing and credential theft. The core fix is to validate redirect destinations using allowlists for external URLs or ensuring local redirects use relative paths starting with `/` but not `//`.

## Key Principles

- Prefer allowlist validation for external URLs against known safe domains
- For internal redirects, validate paths are relative (start with `/` not `//`), contain no backslashes, or match expected patterns
- Reject any path containing `\` - browsers can normalize `/\evil.com` to `//evil.com`, bypassing a `//`-only check
- Use framework-provided redirect methods that include built-in protections
- Never directly insert user input into `Location` headers or redirect mechanisms
- Implement URL parsing to verify scheme, host, and path components before redirecting

## Taint Sinks

`header("Location: " . $userInput)`, `<meta http-equiv="refresh">` with unvalidated URLs

## Remediation Steps

- Identify all redirect points using `header()`, framework redirect methods, or client-side redirects
- Replace direct user input with allowlist validation for external URLs, matching scheme and host with `in_array($value, $allowed, true)` - the strict third argument, or the comparison juggles types
- For local redirects, verify paths start with `/` and don't contain `//` or absolute URLs
- Use `parse_url()` to extract and validate URL components before redirecting
- Apply framework security features (e.g., Laravel's `$request->validate()` with URL rules)
- Add unit tests verifying malicious redirect attempts are blocked
