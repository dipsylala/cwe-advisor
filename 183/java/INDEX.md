# CWE-183: Permissive List of Allowed Inputs - Java

## LLM Guidance

Permissive input validation occurs when regex patterns or validation logic fails to match the complete input, allowing malicious data to bypass checks. In Java, use fully anchored regex patterns with `^` and `$` anchors and call `matches()` instead of `find()` to ensure complete input validation. Use secure APIs like `URI`, `Path`, and `InetAddress` for complex validation scenarios and always enforce length limits to prevent injection attacks.

## Key Principles

- Use `Pattern.matches()` with fully anchored patterns (`^...$`) to validate entire input strings
- Avoid `Matcher.find()` which only matches substrings, creating bypass opportunities
- Implement strict length validation before regex processing to prevent ReDoS attacks
- Use specialized validation classes (`URI`, `Path`, `InetAddress`) for structured data instead of regex
- Apply defence-in-depth with multiple validation layers for critical inputs
- Resolve with `toRealPath()` before comparing, since a lexical `normalize()` cannot see a symlink and the allowlist then approves a path that resolves elsewhere

## Taint Sinks

`Matcher.find()` on unanchored patterns, `Pattern.compile()` without `^...$` anchors, missing length checks before regex

## Remediation Steps

- Replace `Pattern.compile(regex).matcher(input).find()` with `input.matches("^" + regex + "$")`
- Add explicit length checks before validation - `if (input.length() > MAX_LENGTH) throw new ValidationException()`
- Use `URI.create()` for URLs, `Paths.get()` for file paths, and `InetAddress.getByName()` for IPs instead of regex
- Compile patterns with anchors - `Pattern pattern = Pattern.compile("^[a-zA-Z0-9]{3,20}$")`
- Test validation with boundary cases including partial matches, empty strings, and oversized inputs
- Log validation failures for security monitoring
