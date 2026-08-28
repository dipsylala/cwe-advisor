# CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers ('HTTP Request/Response Splitting') - C#

## LLM Guidance

HTTP Response Splitting occurs when attackers inject CRLF (`\r\n`) characters into HTTP headers, enabling them to inject additional headers or response bodies, potentially leading to cache poisoning, XSS, or session hijacking. The vulnerability arises when user input is directly concatenated into HTTP headers without sanitization. Always use ASP.NET Core's built-in methods that automatically sanitize headers and avoid manual header construction.

## Key Principles

- Use ASP.NET Core framework methods (`Redirect()`, `RedirectToAction()`, `Response.Cookies.Append()`) that automatically encode/sanitize values
- Never manually concatenate user input into `Response.Headers` or construct raw HTTP responses
- Reject or strip CRLF and Unicode line terminators from any user input destined for headers: `\r` (U+000D), `\n` (U+000A), U+0085 (NEL), U+2028 (LINE SEPARATOR), U+2029 (PARAGRAPH SEPARATOR)
- Use `Url.IsLocalUrl()` or explicit allowed-origin/path allowlists before redirects
- Enable response header validation in web.config or through middleware
- ASP.NET Core rejects CR and LF in a header value with `InvalidOperationException`, so an unvalidated value is a 500 rather than a split response - a denial of service to fix, not a control to rely on, and it does not apply to bytes written directly to `Response.Body`
- Build a `Content-Disposition` with `ContentDispositionHeaderValue`, which encodes the filename parameter, rather than interpolating a name into the string
- Percent-encode a value that must appear in a header with `UrlEncoder.Default.Encode()` where the header's grammar allows it, rather than filtering characters out
- `Results.Redirect(...)` takes the destination as a value - validate it against an allowlist, since the framework's CR/LF rejection says nothing about where the redirect points

## Taint Sinks

`Response.AddHeader()`, `Response.Headers.Add()`, `Response.Headers["Location"]`, `Response.Redirect()`

## Remediation Steps

- Replace manual `Response.AddHeader()` or `Response.Headers.Add()` calls with framework methods
- Use `Redirect()` or `RedirectToAction()` instead of setting `Location` header manually
- Validate redirect URLs with `Url.IsLocalUrl()` for local redirects or an explicit allowed-origin allowlist for external redirects
- Strip CRLF and Unicode line terminators: `input.Replace("\r", "").Replace("\n", "").Replace("\u0085", "").Replace("\u2028", "").Replace("\u2029", "")`; also strip percent-encoded variants `%0d`, `%0a`
- Set `cookieOptions.HttpOnly = true` and use `Response.Cookies.Append()` for cookies
- ASP.NET Core validates header values by default; avoid bypassing this with lower-level APIs that write raw header bytes
