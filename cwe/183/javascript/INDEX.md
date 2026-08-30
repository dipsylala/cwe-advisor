# CWE-183: Permissive List of Allowed Inputs - JavaScript

## LLM Guidance

CWE-183 occurs when input validation uses overly permissive patterns that fail to reject malicious inputs, allowing attackers to bypass security controls through crafted strings. In JavaScript/TypeScript, this commonly happens with unanchored regex, incomplete URL validation, or loose string matching. Use fully anchored regex patterns (`^...$`), native validation APIs (URL constructor, path.resolve()), Set-based allowlists, and strict length limits to ensure complete input validation.

## Key Principles

- Always anchor regex patterns with `^` and `$` to match entire input
- Prefer native APIs (URL, path) over regex for structured data validation, but don't treat a successful `new URL()` parse as proof the input was well-formed: the WHATWG URL parser silently strips leading/trailing whitespace and embedded tab/newline characters (`new URL("  http://evil.com/  ")` and `new URL("ht\ttp://ev\nil.com/")` both parse cleanly), and a value like `https://good.com@evil.com/` parses with `.hostname === "evil.com"` while `good.com` is only the userinfo - a check against the raw string or a naive `startsWith("https://good.com")` is fooled either way. Always re-check the parsed `.hostname` against the allowlist, never the original string. Separately, `\` is treated the same as `/` for special schemes, so `https://good.com\@evil.com/` keeps `good.com` as the host and folds `@evil.com/` into the path instead - a different normalization surprise, not a host-confusion bypass
- Use Set-based lookups for discrete allowlists instead of pattern matching
- `express.static()` and similar file servers derive `Content-Type` from the stored file's final extension, not from any upload-time check - a file that passed extension validation but is stored with a `.html` name still renders as same-origin HTML/script; serve untrusted uploads with a forced `Content-Disposition: attachment` or from a separate origin
- Enforce strict length limits before validation
- Validate normalized/canonical forms to prevent bypass techniques
- Compare with `path.relative()` rather than `BASE_DIR + path.sep` string prefixing - but on Windows a target on a different drive is returned unchanged rather than prefixed with `..`, so also reject a result that is itself absolute (`path.isAbsolute()`), not just one starting with `..`. Check the *final* extension rather than whether an allowed one appears anywhere - `evil.jpg.php` still contains `.jpg` but its final extension is `.php`. A final-extension check alone does not close `evil.php.jpg` if the server itself is misconfigured to execute any filename containing `.php` (e.g. an Apache `AddHandler` matching on substring) - that is a server-configuration fix, not an application-validation one

## Taint Sinks

unanchored regex (missing `^`/`$`), loose `String.includes()`/`startsWith()` checks, missing length limits

## Remediation Steps

- Replace unanchored regex with fully anchored patterns using `^` and `$`
- Implement Set-based allowlists for known valid values
- Use URL constructor for URL validation and path.resolve() for file paths
- Add maximum length checks before validation logic
- Normalize inputs (lowercase, trim) before allowlist comparison
- Throw errors on validation failure; never fall back to permissive defaults
