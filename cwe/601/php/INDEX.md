# CWE-601: URL Redirection to Untrusted Site ('Open Redirect') - PHP

## LLM Guidance

Open redirect vulnerabilities occur when user-controlled input is used in `header("Location: ...")`, `<meta>` refresh tags, or JavaScript redirects without validation, enabling phishing and credential theft. The core fix is to validate redirect destinations using allowlists for external URLs or ensuring local redirects use relative paths starting with `/` but not `//`.

## Key Principles

- Prefer allowlist validation for external URLs against known safe domains
- For internal redirects, validate paths are relative (start with `/` not `//`), contain no backslashes, or match expected patterns
- Reject any path containing `\` - browsers can normalize `/\evil.com` to `//evil.com`, bypassing a `//`-only check
- Reject tab, CR and LF as well: a browser strips those characters from a URL before resolving it, so a value that arrives pre-decoded as `/<tab>/evil.com` is resolved by the browser as `//evil.com`, while `parse_url()` reports it as an ordinary path with no host and `header()` passes an embedded tab through unchanged
- Use framework-provided redirect methods that include built-in protections
- Never directly insert user input into `Location` headers or redirect mechanisms
- Implement URL parsing to verify scheme, host, and path components before redirecting

## Taint Sinks

`header("Location: " . $userInput)`, `<meta http-equiv="refresh">`

## Remediation Steps

- Identify all redirect points using `header()`, framework redirect methods, or client-side redirects
- Replace direct user input with allowlist validation for external URLs, matching scheme and host with `in_array($value, $allowed, true)` - the strict third argument avoids PHP's pre-8.0 numeric-string type juggling, and the manual still recommends it unconditionally since similar edge cases exist for other types
- For local redirects, verify paths start with `/` and don't contain `//` or absolute URLs
- `parse_url()` is not a validator - the manual's own caution names exactly this use case: "validating an URL against an allow-list of acceptable hostnames with parser A might be ineffective when the actual retrieval of the resource uses parser B that extracts hostnames differently." Prefer the newer `Uri\Rfc3986\Uri`/`Uri\WhatWg\Url` classes the manual now recommends for new code where available, and never treat a `parse_url()` result alone as proof a value is safe
- Laravel's `'url'` validation rule checks that a value is a well-formed URL, optionally with an allowed scheme - it says nothing about whether the *host* is trusted, so `'url:http,https'` passes `https://evil.com` exactly as readily as a same-site link. Use it only as a format check ahead of a separate allowlist or relative-path check, never as the allowlist itself
- Add unit tests verifying malicious redirect attempts are blocked
