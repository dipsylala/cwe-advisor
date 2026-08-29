# CWE-80: Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS) - C#

## LLM Guidance

CWE-80 is the subset of CWE-79 covering injection of script-related HTML tags. In ASP.NET Core, Razor HTML-encodes every C# expression that evaluates to a string, so a finding is usually a construct that opts out of that rather than a missing encoder. Check first which framework the code targets: several of the APIs commonly cited for this weakness exist only on .NET Framework.

## Key Principles

- Rely on Razor's `@variable` syntax, which HTML-encodes by default, and avoid the opt-outs: `@Html.Raw()` and `HtmlString` - the latter documented by Microsoft as a class that "isn't automatically encoded upon output"
- **Know which framework an API belongs to.** `MvcHtmlString` exists only in ASP.NET MVC 5.2 on .NET Framework; `Response.Write()` and `InnerHtml` are `System.Web` and stop at .NET Framework 4.8.1. On ASP.NET Core the equivalent opt-out is `HtmlString`. Naming a Framework-only type in a Core codebase sends the fix somewhere there is nothing to change
- **Do not call `JavaScriptEncoder` inside a Razor expression.** `Encode()` returns a `string`, and Razor HTML-encodes any string expression, so `@JavaScriptEncoder.Default.Encode(value)` is encoded twice and renders visible escapes. Microsoft's stated preference is not to encode into script at all: "The safest way to insert values is to place the value in a data attribute of a tag and retrieve it in your JavaScript", with JavaScript encoding as the fallback for when that is impossible
- `JavaScriptEncoder.Default` does escape the HTML-sensitive characters - Microsoft documents this by contrast, noting `UnsafeRelaxedJsonEscaping` "does not escape HTML-sensitive characters such as `<`, `>`, `&`". Never emit the relaxed encoder's output into a page or a `<script>` element
- Reaching an encoder through `.Default` bypasses configuration: "Customization of the safe list only affects encoders sourced via dependency injection. If you directly access an encoder via `System.Text.Encodings.Web.*Encoder.Default`, only the default safe list is used, Basic Latin." Inject `HtmlEncoder`/`JavaScriptEncoder`/`UrlEncoder` where the safe list has been widened
- `HttpUtility.HtmlEncode` is the `System.Web` one; its own documentation says "To encode or decode values outside of a web application, use the `WebUtility` class". `WebUtility.HtmlEncode` escapes the five characters and is available everywhere
- Sanitize rich content with the `HtmlSanitizer` package (namespace `Ganss.Xss` from 8.0.601; the package id is `HtmlSanitizer`, not the namespace). **Operative floor 9.0.967** - and note the shape of its history: the style-tag, foreign-content and template-tag bypasses were all unlocked by *permissive configuration*, which is exactly what a rich-text editor integration does. The highest-severity issue, a CSS-removal denial of service fixed in 9.0.967, carries no CVE at all, so a CVE-keyed dependency scan misses it
- Sanitization supplements encoding, it does not replace it. Microsoft: "Never rely on validation alone. Always encode untrusted input before output, no matter what validation or sanitization is performed" - and, on where encoding belongs, "encoding takes place at the point of output and encoded values should never be stored in a database". Where rich input is genuinely needed, Microsoft suggests Markdown with a parser that strips embedded HTML as the safer option

## Taint Sinks

`Html.Raw()`, `HtmlString`, `MvcHtmlString` (.NET Framework), `InnerHtml` (.NET Framework), `Response.Write()` (.NET Framework), `JavaScriptEncoder.UnsafeRelaxedJsonEscaping`

## Remediation Steps

- Replace `@Html.Raw(userInput)` with `@userInput` to restore automatic encoding
- For a value that must reach JavaScript, render it into a data attribute and read it from script, rather than encoding it into a `<script>` block
- Implement CSP headers via middleware with `context.Response.Headers.Append(...)`, the indexer, or the typed `Headers.ContentSecurityPolicy` property (6.0+). `Headers.Add` throws `ArgumentException` on a duplicate key and is flagged by analyzer ASP0019, which Microsoft says not to suppress - and a Blazor Web App on .NET 8+ already emits a `Content-Security-Policy` header, so the collision is real
- For rich text, sanitize with `HtmlSanitizer` at 9.0.967 or later, and review any element or attribute added to its allowlist against the bypass history above
- Encode at output rather than storing encoded values; keep sanitized markup and the encoding step separate
- Audit for the framework-appropriate raw-output sinks and for string concatenation building JavaScript
- Test with `<script>alert(1)</script>` and `<img src=x onerror=alert(1)>`, and confirm legitimate text containing `<`, `>` and `&` still displays correctly
