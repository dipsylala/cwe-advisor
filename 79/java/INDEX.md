# CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - Java

## LLM Guidance

Cross-Site Scripting (CWE-79) occurs when untrusted data is included in web pages without proper encoding, allowing attackers to inject malicious scripts that execute in victim browsers to steal sessions, harvest credentials, or distribute malware. Java applications must encode all user-controlled output using context-appropriate methods (HTML, JavaScript, URL, CSS). Fix by applying output encoding at every injection point based on the context where data appears.

## Key Principles

- Always encode output based on context (HTML entity encoding for HTML content, JavaScript encoding for JS contexts, URL encoding for URLs)
- Use established encoding libraries like OWASP Java Encoder or Spring's HtmlUtils rather than custom sanitization, choosing the method for the context: `Encode.forHtml()`, `Encode.forHtmlAttribute()`, `Encode.forJavaScript()`, `Encode.forUriComponent()`
- Treat the escaping opt-outs as sinks: JSTL `<c:out escapeXml="false">`, Struts `escape="false"`, Thymeleaf `th:utext`, unescaped inlining `[(...)]`, and `th:inline="javascript"` blocks. `th:attr` is not one of them - Thymeleaf escapes the attribute values it writes; the attribute-level risk is a `javascript:` URL reaching `th:href`/`th:src`, which no amount of escaping addresses
- Validate and sanitize input as defence-in-depth, but never rely on input validation alone
- Set Content Security Policy (CSP) headers to restrict script execution sources
- Use HTML templating engines with auto-escaping enabled by default

## Taint Sinks

`response.getWriter().println()`, `PrintWriter.print()`, JSP `<%= expr %>`, Thymeleaf `th:utext`, `<c:out escapeXml="false">`

## Remediation Steps

- Identify all locations where user input or external data is rendered in responses
- Apply context-appropriate encoding using OWASP Java Encoder at each output point
- Render through the escaping construct rather than hunting for an engine-wide switch: JSP has no auto-escape setting, so replace `<%= %>` with JSTL `<c:out value="${...}" />`; Thymeleaf already escapes `th:text`, so the fix there is deleting `th:utext`; FreeMarker is the only one with a real switch - set `output_format` to `HTML`
- Implement CSP headers with strict policies (`default-src 'self'`)
- Review and test all dynamic content rendering paths
