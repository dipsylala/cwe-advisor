# CWE-183: Permissive List of Allowed Inputs

## LLM Guidance

The list is a list of *allowed* inputs and it is too wide - as against a pattern that is simply wrong, which is CWE-185, or an over-permissive CORS origin list, which is CWE-942.

## Key Principles

- Use strict allowlists with default-deny; reject everything not explicitly permitted
- Anchor both ends, and ask the API for a whole-string match rather than a search: most regex APIs search by default, so an unanchored pattern answers "does an allowed value appear somewhere" when the question was "is the input an allowed value". Anchoring only one end leaves the other open to appended or prepended content
- Avoid overly broad wildcards (`.+`, `.*`, `\w+`), and prefer an exact-match set or enum over a pattern wherever the permitted values are a known fixed list
- Validate against exact expected formats, not permissive patterns
- Check position, not presence: confirming an allowed extension appears *somewhere* accepts `malware.exe.jpg` and `shell.jpg.php`, each chosen for a server that resolves a different extension from the one the check found
- Parse structured values rather than testing their string form: `startsWith("http")` is satisfied by `httpx:` and by `http:evil`, and lengthening the prefix does not repair the approach - decide on the parsed scheme and host
- Apply validation at all trust boundaries before dangerous operations
- Consider canonicalization and encoding variations when defining allowed inputs

## Remediation Steps

- Locate validation logic in your code (regex patterns, allowlists, format checks)
- Review allowlists for overly broad patterns or missing constraints
- Replace permissive patterns with strict, anchored validation (e.g., `^[a-z]{3,10}$` instead of `\w+`)
- Add validation for inputs that lack security checks
- Test edge cases - special characters, encoding variations, path traversal sequences
- Ensure validated data is used safely in downstream operations (SQL, file paths, commands)
