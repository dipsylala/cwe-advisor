# CWE-183: Permissive List of Allowed Inputs - Python

## LLM Guidance

CWE-183 occurs when input validation uses overly permissive patterns that fail to match the entire input string, allowing attackers to inject malicious content before or after valid data. Prefer `re.fullmatch()` over anchoring with `^`/`$`, validate complex inputs with specialized libraries like `pathlib` and `ipaddress`, and enforce strict length limits.

## Key Principles

- Prefer `re.fullmatch()` over `^...$` anchors: without `re.MULTILINE`, `$` still matches the position just before a single trailing newline, so `re.match("^value$", "value\n")` succeeds - a real bypass for any check meant to reject trailing-newline payloads (header injection, smuggling). `fullmatch()` has no such exception; if a pattern must be anchored explicitly, use `\A` and `\Z`, not `^` and `$`
- Use Python's specialized validation libraries (`pathlib`, `ipaddress`, `urllib.parse`) instead of custom regex - a character-class allowlist constrains the alphabet, not the grammar, so `^[a-zA-Z0-9._/-]+$` still admits `../../etc/passwd` since every character in it is individually permitted; only a resolve-and-contain check catches this
- `os.path.normpath()`/`os.path.abspath()` alone are not sufficient for path safety: both collapse `..` sequences textually but never touch the filesystem, so a symlink planted inside the allowed directory still escapes it. Use `Path.resolve()` (or `os.path.realpath()`), which does follow symlinks, before the containment check
- Validate against strict allowlists of permitted values using sets or enums
- Enforce input length limits before pattern matching
- Fail closed on validation errors with explicit rejection
- Check the final suffix (`Path(name).suffix`) against the allowlist rather than testing whether an allowed extension appears in the name, which `evil.jpg.php` satisfies

## Taint Sinks

`re.search()`/`re.match()` without anchors, unanchored regex patterns, missing length checks before validation

## Remediation Steps

- Replace `re.search()` or `re.match()` with `re.fullmatch()` for complete validation
- Where a pattern can't be converted to `fullmatch()`, anchor it with `\A` and `\Z` rather than `^` and `$`, which do not reject a trailing newline
- Use `pathlib.Path.resolve()` to canonicalize, then confirm containment with `resolved.is_relative_to(base_dir)` rather than a string prefix comparison
- Apply the `ipaddress` module for IP address validation instead of regex - require Python 3.9.5+ (or a patched 3.8.x), since earlier versions tolerate ambiguous leading zeros in IPv4 octets that later releases reject as a security fix
- Check input length with `len()` before validation to prevent DoS
- Use sets or frozensets for exact string matching against allowlists
