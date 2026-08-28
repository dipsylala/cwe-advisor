# CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') - C#

## LLM Guidance

XSS occurs when untrusted data is included in web output without proper encoding, allowing attackers to inject malicious scripts into victim browsers. In C#/ASP.NET, use built-in auto-encoding features and context-specific encoders to prevent malicious content from executing.

## Key Principles

- Use Razor's automatic encoding with `@variable` syntax (ASP.NET Core and MVC). Microsoft describes
  it as applying HTML *attribute* encoding rules and warns that `@` is safe only in an HTML context -
  it does not make a value safe inside a `<script>` block, an `on*` handler, or an `href`. Note also
  that `HtmlString` and anything returning `IHtmlContent` are exempt from it by design
- Apply context-specific encoders from `System.Text.Encodings.Web`: `HtmlEncoder` for HTML, `JavaScriptEncoder` for JS contexts, `UrlEncoder` for URLs
- Outside Razor (Web Forms, handlers, hand-built responses) use `System.Net.WebUtility.HtmlEncode()` or `System.Web.HttpUtility.HtmlEncode()` for markup. Neither belongs inside a `<script>` block: HTML encoding does escape `<`, but a `<script>` element is raw text where the browser never decodes entities, so the value arrives in the JS string still spelled `&quot;` while the backslashes and U+2028/U+2029 line terminators that can break the literal go untouched. Use `HttpUtility.JavaScriptStringEncode()` or `JavaScriptEncoder.Default.Encode()` there
- Sanitize rich HTML before `@Html.Raw()` with the third-party `HtmlSanitizer` package (NuGet
  `Ganss.Xss`, formerly `HtmlSanitizer`) - it is not a Microsoft component, so treat its version as
  part of the fix
- Implement Content Security Policy headers for defence-in-depth
- Validate input format as secondary defence, never rely on it alone

## Taint Sinks

`@Html.Raw()`, `Response.Write()`, `Literal.Text`, `HttpResponse.WriteAsync()`, Blazor `MarkupString`

## Remediation Steps

- Replace `@Html.Raw()` with Razor's `@variable` auto-encoding. `Response.Write()` and `Literal.Text`
  are Web Forms and `System.Web`, where Razor is not available - encode explicitly there with
  `WebUtility.HtmlEncode()`, or set `Literal.Mode` to `LiteralMode.Encode`
- Use `HtmlEncoder.Default.Encode()` for explicit HTML encoding in controllers or classic ASP.NET
- Prefer Microsoft's own first recommendation for script contexts: put the value in a data attribute
  on an element and read it from JavaScript at runtime, so the value never crosses into script source.
  Where that is impractical, `JavaScriptEncoder.Default.Encode()` is the fallback - and do not
  substitute `JavaScriptEncoder.UnsafeRelaxedJsonEscaping`, which deliberately does not escape `<`,
  `>` or `&`
- Use `UrlEncoder.Default.Encode()` for query-string *values*. Microsoft warns against placing
  untrusted input in a URL path at all, so encoding is not the answer there - and no encoder makes an
  attacker-chosen scheme safe, so validate that a URL is `http`/`https` before emitting it rather than
  relying on encoding to neutralise `javascript:`
- For rich text editors, integrate HtmlSanitizer with allowlist of safe tags before rendering with `@Html.Raw()`
- Add CSP middleware to restrict script sources and enforce 'self' policy
