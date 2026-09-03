# CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Java

## LLM Guidance

Cross-Site Scripting (CWE-79) occurs when untrusted data is included in web pages without proper encoding, allowing attackers to inject malicious scripts that execute in victim browsers to steal sessions, harvest credentials, or distribute malware. Java applications must encode all user-controlled output using context-appropriate methods (HTML, JavaScript, URL, CSS). Fix by applying output encoding at every injection point based on the context where data appears.

## Key Principles

- Always encode output based on context (HTML entity encoding for HTML content, JavaScript encoding for JS contexts, URL encoding for URLs)
- Use the OWASP Java Encoder rather than custom sanitization, choosing the method for the context:
  `Encode.forHtml()`, `Encode.forHtmlAttribute()`, `Encode.forJavaScript()`, `Encode.forCssString()`,
  `Encode.forUriComponent()`. Spring's `HtmlUtils` is not an equivalent - it does HTML entity escaping
  only and has no attribute, JavaScript, URL or CSS method, so it cannot satisfy the context rule
- `Encode.forJavaScript()` requires the caller to supply the surrounding quotation marks; applied to
  an unquoted assignment it does not make the value safe. And `Encode.forUriComponent()` encodes a
  *component*, so it cannot be wrapped around a whole URL - a `javascript:` scheme is closed by an
  allowlist of `http`/`https`, not by encoding (the encoder's own deprecated `forUri` documents
  exactly this trap)
- Treat the escaping opt-outs as sinks: JSTL `<c:out escapeXml="false">`, Struts `escape="false"`, Thymeleaf `th:utext`, unescaped inlining `[(...)]`, and `th:inline="javascript"` blocks. `th:attr` is not one of them - Thymeleaf escapes the attribute values it writes; the attribute-level risk is a `javascript:` URL reaching `th:href`/`th:src`, which no amount of escaping addresses
- Encoding and sanitizing answer different questions. Encode when the value is text. When the value is meant to carry markup - a field named `bodyHtml`, a rich-text editor's output, a CMS body - swapping `th:utext` for `th:text` closes the XSS by printing the tags as literal text, a functional regression that is silent unless the write-up says so. For markup, sanitize with the OWASP Java HTML Sanitizer (artifact `com.googlecode.owasp-java-html-sanitizer:owasp-java-html-sanitizer`, date-versioned - `20240325.1` at the time of writing) using an explicit `PolicyFactory` such as `Sanitizers.FORMATTING.and(Sanitizers.BLOCKS)`, and keep `th:utext` for the sanitized result. The Java Encoder has no method for this - it escapes, it does not allowlist tags
- Validate and sanitize input as defence-in-depth, but never rely on input validation alone
- Set Content Security Policy (CSP) headers to restrict script execution sources
- Use HTML templating engines with auto-escaping enabled by default

## Taint Sinks

`response.getWriter().println()`, `PrintWriter.print()`, JSP `<%= expr %>`, Thymeleaf `th:utext`, `<c:out escapeXml="false">`

## Remediation Steps

- Identify all locations where user input or external data is rendered in responses
- Apply context-appropriate encoding using OWASP Java Encoder at each output point
- Render through the escaping construct rather than hunting for an engine-wide switch: JSP has no auto-escape setting, so replace `<%= %>` with JSTL `<c:out value="${...}" />`, whose `escapeXml` defaults to true. EL resolves page, request, session and application attributes, not a scriptlet's Java locals: `<c:out value="${name}" />` for a `String name` declared in `<% %>` renders empty, so either publish the value with `pageContext.setAttribute("name", name)` first or keep the scriptlet and wrap it, `<%= Encode.forHtml(name) %>`. Note too that `<c:out>` converts only `<`, `>`, `&`, `'` and `"`. That set covers an HTML body and a *quoted* attribute, and nothing else - it is not a fix for an unquoted attribute, nor for a value landing in `<script>`, `href` or `style`; Thymeleaf already escapes `th:text`, so the fix there is deleting `th:utext` - unless the field is intentionally HTML, in which case sanitize with an allowlist policy (see Key Principles) and keep `th:utext` for the sanitized value; FreeMarker is the only one with a real switch - set `output_format` to `HTML`, which needs FreeMarker 2.3.24 or later and `incompatible_improvements` at 2.3.24 for the default to engage; below that the setting silently does nothing and the deprecated `escape` directive is the alternative
- Implement a strict CSP built on a per-response nonce or hash rather than an allowlist, with
  `object-src 'none'` and `base-uri 'none'`
- Review and test all dynamic content rendering paths
