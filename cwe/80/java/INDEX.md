# CWE-80: Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS) - Java

## LLM Guidance

CWE-80 is the subset of CWE-79 covering injection of script-related HTML tags. In Java the answer depends entirely on which view technology is rendering, because their defaults are opposite: Thymeleaf escapes unless you ask it not to, JSP never escapes at all, and FreeMarker escapes only once an output format has been associated with the template. Establish which one is in play before deciding what the fix is.

## Key Principles

- **JSP has no auto-escaping and no switch to enable one.** `<%= %>` compiles to `out.print(expression)`, and EL `${...}` is equally unescaped - the specification's own remedy is external: "In cases where escaping is desired (for example, to help prevent cross-site scripting attacks), the JSTL core tag `<c:out>` can be used." `<c:out>` escapes `<`, `>`, `&`, `'` and `"`, with `escapeXml` defaulting to true. Its taglib URI differs by version: `jakarta.tags.core` in Jakarta Tags 3.0, `http://java.sun.com/jsp/jstl/core` in legacy JSTL
- **Thymeleaf escapes by default and has nothing to enable.** `th:text` escapes; `th:utext` does not. The sink that gets missed is inline expression syntax: `[[...]]` corresponds to `th:text` and escapes, `[(...)]` corresponds to `th:utext` and does not - and inlining is "active by default in the body of every tag"
- **FreeMarker is the opposite: auto-escaping is off unless configured.** The default output format is `undefined`, which "does no escaping". Turning it on needs FreeMarker **2.3.24+** plus either the `.ftlh`/`.ftlx` extensions with `incompatible_improvements` at 2.3.24 or higher (the vendor calls this "the recommended way"), or an explicit `output_format`/`template_configurations`. Check `${.output_format}` in a live template rather than assuming. Its unescaped constructs are `?no_esc`, `<#noautoesc>` and `<#ftl autoesc=false>`, and its `JavaScript`, `JSON` and `CSS` output formats are documented as not escaping - selecting a format is not the same as escaping
- Note that `${...}` means opposite things across these: unescaped in JSP, escaped inside Thymeleaf's `th:text`. The token alone does not tell you whether a finding is real
- For manual encoding use the OWASP Java Encoder (`org.owasp.encoder:encoder`, 1.4.0), and pick the method by context. `Encode.forHtml()` covers both text and attribute positions; `Encode.forHtmlAttribute()` omits `>` and **requires the caller to supply the surrounding quotes**; `Encode.forHtmlContent()` does not escape quote characters and is unsafe in an attribute. The javadoc's own carve-out matters: `forHtmlAttribute` must not be used for `on*` event handlers or URL-valued attributes - use `Encode.forJavaScript()` and `Encode.forUriComponent()` there
- Spring's escaping is two separate things. `HtmlUtils.htmlEscape` escapes the full HTML 4.01 entity set. The `defaultHtmlEscape` context-param is narrower than it sounds: it is read from `web.xml`, consumed only by Spring's own JSP tag library, and **defaults to false**. It does not affect Thymeleaf, FreeMarker, or `@ResponseBody` output
- Writing markup through `response.getWriter()` bypasses whatever escaping the template layer applies, so those call sites need the encoder applied explicitly - and the sink is the writer, not one method on it: `print`, `println`, `printf` and `append` are the same exposure, as is `getOutputStream()`
- `HttpOnly` on session cookies is mitigation, not remediation. Jakarta's own javadoc hedges it as something that "may therefore help mitigate certain kinds of cross-site scripting attacks", and OWASP is blunter: cookie attributes "don't prevent the execution of malicious content or address the root cause". Set it through `SessionCookieConfig` for session cookies, and treat CSP the same way - OWASP's position is that it "should not be relied upon as the only defensive mechanism against XSS"

## Taint Sinks

`<%= %>` and `${...}` in JSP, `th:utext`, Thymeleaf `[(...)]` inlining, FreeMarker `?no_esc`/`<#noautoesc>`/`<#ftl autoesc=false>`, `Encode.forHtmlContent()` used in an attribute, `response.getWriter().write()`/`print()`/`println()`, `response.getOutputStream()`

## Remediation Steps

- Identify the view technology first, since the default differs and so does the fix
- Treat one finding as a population, not a line. CWE-80 names only element content, so a codebase that failed there has usually failed in the contexts it does not name - attributes, `href`/`src`, inline script. Search for `escapeXml="false"`, `th:utext`, `escape="false"` and `${` outside `<c:out>` rather than fixing only the reported line
- In JSP, replace direct expressions and bare EL output with `<c:out>`, matching the taglib URI to the Jakarta or legacy namespace
- In Thymeleaf, replace `th:utext` with `th:text` and `[(...)]` with `[[...]]` for untrusted data
- In FreeMarker, associate an escaping output format with the template - the `.ftlh`/`.ftlx` convention on 2.3.24+ - and verify with `${.output_format}` rather than assuming it applies
- Use the OWASP Java Encoder for manual encoding in servlets, choosing the method for the context and quoting attributes where `forHtmlAttribute` is used
- Apply the encoder explicitly at any `response.getWriter()` or `getOutputStream()` call site
- Add CSP headers and session-cookie flags as defence-in-depth, not as the fix
- Test with `<script>alert(1)</script>` and `<img src=x onerror=alert(1)>`, and confirm legitimate text containing `<`, `>` and `&` still displays correctly
