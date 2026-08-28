# CWE-80: Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS)

## LLM Guidance

CWE-80 occurs when applications fail to properly neutralize script-related HTML tags (`<script>`, `<img>`, `<iframe>`) in web output, allowing attackers to inject malicious scripts that execute in victims' browsers. This is a specific subset of CWE-79, scoped by MITRE to the `<`, `>` and `&` characters that let a value become a tag. The fix is identical to CWE-79's, so use CWE-79's guidance for anything beyond plain tag injection - an attribute, a `<script>` block, a URL, or a CSS value. The core fix is applying context-appropriate output encoding to prevent untrusted input from being interpreted as executable markup.

## Key Principles

- Never include untrusted input in HTML output without context-appropriate encoding
- Ensure data cannot be interpreted as executable markup or script
- Apply encoding based on specific output context (HTML body, attribute, JavaScript, CSS, URL)
- Use context-aware output encoding as the primary defence layer
- Encode at output time, not at storage time - encoding on the way in breaks search and sorting, and the stored value is still wrong for whichever context it is later rendered into
- Filter-and-strip is not encoding: a denylist is defeated by `<scr<script>ipt>` (which reassembles once the inner match is removed) and by vectors that need no `<script>` tag at all, such as `<img src=x onerror=alert(1)>`
- Encode once: applying an encoder to already-encoded data renders visible entities (`&amp;lt;script&amp;gt;`) rather than the intended text, so track whether a value has been encoded already
- Never bypass a template engine's auto-escaping for untrusted data (`@Html.Raw()`, `|safe`, `th:utext`, `v-html`, `dangerouslySetInnerHTML`); sanitize to safe HTML first if markup genuinely must be rendered

## Remediation Steps

- Identify all sources of untrusted data (user input, databases, external files, network requests, cookies, headers)
- Trace data transformations from source to output sink
- Locate where data is rendered (response writing, template rendering, DOM manipulation)
- Determine the specific output context where data appears
- Check for missing or inadequate encoding/escaping functions
- Apply context-aware output encoding at all output points, on the server - client-side validation is bypassable with any HTTP client
- Test with tag-injection payloads (`<script>alert(1)</script>`, `<img src=x onerror=alert(1)>`) and confirm legitimate text containing `<`, `>`, and `&` still displays correctly
