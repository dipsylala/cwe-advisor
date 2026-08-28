# CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - C#

## LLM Guidance

XSS occurs when untrusted data is included in web output without proper encoding, allowing attackers to inject malicious scripts into victim browsers. In C#/ASP.NET, use built-in auto-encoding features and context-specific encoders to prevent malicious content from executing.

## Key Principles

- Use Razor's automatic HTML encoding with `@variable` syntax (ASP.NET Core/MVC)
- Apply context-specific encoders from `System.Text.Encodings.Web`: `HtmlEncoder` for HTML, `JavaScriptEncoder` for JS contexts, `UrlEncoder` for URLs
- Outside Razor (Web Forms, handlers, hand-built responses) use `System.Net.WebUtility.HtmlEncode()` or `System.Web.HttpUtility.HtmlEncode()`; neither is a substitute for the JavaScript encoder inside a `<script>` block, where the literal sequence `</script>` closes the block from inside a JS string
- Sanitize rich HTML with HtmlSanitizer library before using `@Html.Raw()`
- Implement Content Security Policy headers for defence-in-depth
- Validate input format as secondary defence, never rely on it alone

## Taint Sinks

`@Html.Raw()`, `Response.Write()`, `Literal.Text`, `HttpResponse.WriteAsync()`

## Remediation Steps

- Replace `@Html.Raw()`, `Response.Write()`, and Literal controls with Razor's `@variable` auto-encoding
- Use `HtmlEncoder.Default.Encode()` for explicit HTML encoding in controllers or classic ASP.NET
- Apply `JavaScriptEncoder.Default.Encode()` when embedding data in `<script>` blocks or JS event handlers
- Use `UrlEncoder.Default.Encode()` for query parameters and URL components
- For rich text editors, integrate HtmlSanitizer with allowlist of safe tags before rendering with `@Html.Raw()`
- Add CSP middleware to restrict script sources and enforce 'self' policy
