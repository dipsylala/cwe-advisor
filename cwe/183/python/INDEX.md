# CWE-183: Permissive List of Allowed Inputs - Python

## LLM Guidance

CWE-183 occurs when input validation uses overly permissive patterns that fail to match the entire input string, allowing attackers to inject malicious content before or after valid data. Use fully anchored regex patterns with `^` and `$` or `re.fullmatch()`, validate complex inputs with specialized libraries like `pathlib` and `ipaddress`, and enforce strict length limits.

## Key Principles

- Use `re.fullmatch()` or anchor patterns with `^...$` to ensure complete string matching
- Use Python's specialized validation libraries (`pathlib`, `ipaddress`, `urllib.parse`) instead of custom regex
- Validate against strict allowlists of permitted values using sets or enums
- Enforce input length limits before pattern matching
- Fail closed on validation errors with explicit rejection
- Check the final suffix (`Path(name).suffix`) against the allowlist rather than testing whether an allowed extension appears in the name, which `evil.jpg.php` satisfies

## Taint Sinks

`re.search()`/`re.match()` without anchors, unanchored regex patterns, missing length checks before validation

## Remediation Steps

- Replace `re.search()` or `re.match()` with `re.fullmatch()` for complete validation
- Add anchors `^` and `$` to all existing regex patterns if not using `fullmatch()`
- Use `pathlib.Path.resolve()` to canonicalize, then confirm containment with `resolved.is_relative_to(base_dir)` rather than a string prefix comparison
- Apply the `ipaddress` module for IP address validation instead of regex
- Check input length with `len()` before validation to prevent DoS
- Use sets or frozensets for exact string matching against allowlists
