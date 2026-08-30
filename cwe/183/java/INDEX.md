# CWE-183: Permissive List of Allowed Inputs - Java

## LLM Guidance

Permissive input validation occurs when regex patterns or validation logic fails to match the complete input, allowing malicious data to bypass checks. In Java, call `matches()` instead of `find()` to ensure the entire input is matched - `matches()` already attempts the full region, so `^...$` adds no protection over it. Use secure APIs like `URI`, `Path`, and `InetAddress` for complex validation scenarios and always enforce length limits to prevent injection attacks.

## Key Principles

- Use `Pattern.matches()`/`String.matches()` to validate the entire input string - it already requires a full-region match, so `find()`-to-`matches()` is the fix, not adding anchors
- Avoid `Matcher.find()` which only matches substrings, creating bypass opportunities
- If a pattern must carry explicit anchors (e.g. embedded in a larger expression), use `\A` and `\z`, not `^` and `$`: without `Pattern.MULTILINE`, `$` is defined identically to `\Z` - it matches just before a single trailing line terminator - so `"value\n".matches("^value$")` returns `true`, a real bypass for any check meant to reject a trailing-newline payload. Only `\z` is the absolute end of input
- Implement strict length validation before regex processing to prevent ReDoS attacks
- Use specialized validation classes (`URI`, `Path`, `InetAddress`) for structured data instead of regex
- Apply defence-in-depth with multiple validation layers for critical inputs
- Resolve with `toRealPath()` before comparing, since a lexical `normalize()` cannot see a symlink and the allowlist then approves a path that resolves elsewhere

## Taint Sinks

`Matcher.find()` on unanchored patterns, missing length checks before regex

## Remediation Steps

- Replace `Pattern.compile(regex).matcher(input).find()` with `input.matches(regex)` (no anchors needed - `matches()` already requires the whole input)
- Add explicit length checks before validation - `if (input.length() > MAX_LENGTH) throw new ValidationException()`
- Use `URI.create()` for URLs, `Paths.get()` for file paths, and `InetAddress.getByName()` for IPs instead of regex
- Where a pattern is embedded in a larger expression and needs its own anchors, use `\A` and `\z` - `Pattern pattern = Pattern.compile("\\A[a-zA-Z0-9]{3,20}\\z")`
- Test validation with boundary cases including partial matches, empty strings, and oversized inputs
- Log validation failures for security monitoring
