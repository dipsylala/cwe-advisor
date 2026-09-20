# CWE-601: URL Redirection to Untrusted Site ('Open Redirect')

## LLM Guidance

The redirect is sent to the *browser*; where the server itself fetches the attacker-chosen URL, that is CWE-918. The usual bypass is a value that looks same-site - a scheme-relative `//evil.com`, a backslash, or a userinfo segment - so validate the parsed result rather than the string.

## Key Principles

- Never trust user input for redirect destinations
- Use server-defined redirect targets from an allowlist of approved URLs
- Validate redirect parameters against exact matches, not pattern matching
- Prefer indirect references (IDs/keys) over direct URL parameters
- Reject redirects to external domains by default

## Remediation Steps

- Identify the vulnerability - Review security findings for the file, line number, and parameters controlling redirects (`?next=`, `?redirect=`, `?returnUrl=`)
- Trace data flow - Follow how untrusted input flows to the redirect-issuing function (see the language-specific guidance's Taint Sinks for concrete function names)
- Implement allowlist validation - Create a server-side list of permitted redirect destinations and validate against exact matches
- Use indirect references - Replace direct URL parameters with lookup keys that map to server-defined destinations
- Validate strictly - Ensure redirects are relative paths or exact matches to allowlisted absolute URLs
- Reject external URLs - Block redirects to domains outside your application unless explicitly required and allowlisted
