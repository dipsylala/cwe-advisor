# CWE-159: Improper Handling of Invalid Use of Special Elements

## LLM Guidance

Improper handling of invalid special elements occurs when applications fail to properly validate, encode, or reject special characters (metacharacters) that have meaning in specific contexts (SQL, shell, HTML, regex, file paths), enabling injection attacks.

## Key Principles

- Canonicalize and validate special characters/encodings before processing
- Never assume downstream code handles special elements safely
- Apply context-specific encoding for each target context (SQL, shell, HTML, XML, regex, file paths) - and note the contexts are not interchangeable: HTML entity encoding is right in element content and a *quoted* attribute, insufficient in an unquoted attribute (a space starts a new one), wrong inside a `<script>` block where the parser is reading JavaScript, and beside the point in an `href`, where `javascript:alert(1)` contains no character an HTML encoder touches and a scheme check is what is needed
- Where the finding names a specific sink, prefer that entry's guidance: SQL (CWE-89), OS command (CWE-78), XSS (CWE-79), NoSQL (CWE-943), CRLF (CWE-93) - each carries concrete remediation this general page cannot
- Validate input against allowlists rather than blocklists of special characters - which characters are special is a property of the *sink*, not of the request, so an entry-point denylist has to anticipate a grammar it cannot see
- Canonicalize before validating: an allowlist applied to a still-encoded value passes input that only becomes special once something downstream decodes it
- Reject or encode metacharacters at input boundaries before they reach sensitive operations

## Remediation Steps

- Identify vulnerable code. Locate where untrusted data with special characters reaches sensitive operations (queries, commands, templates)
- Determine target context. Identify whether data flows to SQL, shell, HTML, XML, regex, file path, or other interpreters
- Trace data flow. Map how untrusted input (user data, files, network requests) flows from source to sink
- List dangerous metacharacters. Document which special characters are dangerous in the specific context
- Apply context-specific encoding. Use parameterized queries (SQL), command arrays (shell), HTML entity encoding, or context-appropriate escaping
- Validate and canonicalize. Normalize encodings and validate against allowlists before use
