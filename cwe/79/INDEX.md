# CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

## LLM Guidance

Cross-Site Scripting (XSS) occurs when untrusted data is included in web pages without proper validation or encoding, allowing attackers to inject malicious scripts that execute in victims' browsers. The vulnerability can appear in various contexts including HTML content, attributes, JavaScript, CSS, or URLs.

## Key Principles

- Never render untrusted input directly into executable browser contexts-ensure data remains data, not code
- Apply context-aware output encoding specific to where data appears (HTML encoding differs from JavaScript/URL encoding)
- Treat all external sources as untrusted: user input, databases, external APIs, cookies, headers
- Use defence-in-depth with Content Security Policy (CSP) as a secondary layer
- Validate input format where possible, but rely on output encoding as primary defence; blocklisting `<script>` or `on\w+=` patterns only closes the examples the author thought of, and is defeated by case variation, `<svg onload=>`/`<img onerror=>`, and encoded payloads
- Encode at each output sink, not once on input: a value encoded for HTML body text is still unsafe inside a `<script>` block, an event-handler attribute, a URL, or a CSS value, and one stored value is often rendered into several of those contexts
- Never pass untrusted data through a template or framework auto-escaping bypass; treat any API whose name contains "raw", "unsafe", "bypass", "dangerously", or "trust" as a sink requiring sanitized HTML, not raw input

## Remediation Steps

- Identify sources: Locate all untrusted data entry points (user input, external files, databases, network requests, cookies, headers)
- Trace data flow: Follow transformations from source through the application to output
- Determine output context: Identify where data is rendered (HTML body, attribute, JavaScript, CSS, URL)
- Apply context-specific encoding: Use appropriate encoding functions for each context at every data sink
- Verify encoding presence: Audit code for missing encoding/escaping at rendering points
- Test defences: Validate with XSS payloads for each context (HTML body, attribute breakout, `javascript:` URI, script-block breakout) and confirm legitimate content containing `<`, `&`, and quotes still renders correctly
- Add CSP as a backstop, not the fix: a policy does not remove the unencoded output, and a permissive `script-src` or an existing inline handler still allows execution
