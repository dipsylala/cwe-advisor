# CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute - C#

## LLM Guidance

In ASP.NET Core, cookies created without `CookieOptions.Secure = true` can be transmitted over plaintext HTTP connections, exposing session tokens and authentication cookies to network interception. Set the `Secure` flag on all sensitive cookies, configure global cookie policy via `services.Configure<CookiePolicyOptions>()`, and enforce HTTPS site-wide with HSTS.

## Key Principles

- Set `Secure = true` on every `CookieOptions` used with `Response.Cookies.Append()`
- Configure `CookiePolicyOptions.Secure = CookieSecurePolicy.Always` globally to enforce the flag on all cookies
- Use ASP.NET Core's built-in session and authentication cookie configuration (both have `SecurePolicy` settings)
- Combine with `HttpOnly = true` and `SameSite = SameSiteMode.Strict` for defence-in-depth
- Enable HSTS (`UseHsts()`) so browsers only connect over HTTPS
- `CookieSecurePolicy.SameAsRequest` never downgrades a cookie that is already secure, but over HTTP it takes no action at all, so it is not equivalent to `Always`. `CookieSecurePolicy.None` is also a no-op, not a forced clear - it neither sets nor unsets `Secure`, so a cookie individually created with `Secure = true` stays secure even under a global `None` policy
- Behind a TLS-terminating proxy the request looks like HTTP to Kestrel unless forwarded headers are processed, which is what silently turns `SameAsRequest` into "never secure"
- A `__Host-` name prefix makes the browser reject a cookie that loses the flag, so a misconfiguration fails visibly - apply it only once the flag is confirmed on the wire

## Taint Sinks

`Response.Cookies.Append()` with `Secure` unset, `CookieOptions` without `Secure = true`, `CookiePolicyOptions.Secure` left at default

## Remediation Steps

- Find all `Response.Cookies.Append()` calls and add `Secure = true` to their `CookieOptions`
- In `Program.cs`, add `app.UseCookiePolicy()` and configure `services.Configure<CookiePolicyOptions>(o => o.Secure = CookieSecurePolicy.Always)` and `o.HttpOnly = HttpOnlyPolicy.Always` - register `UseCookiePolicy()` before `UseAuthentication()` and any session middleware, or the global policy never reaches the cookies those middleware issue
- For authentication cookies, set `options.Cookie.SecurePolicy = CookieSecurePolicy.Always` in `AddCookie()` configuration
- For session cookies, configure `options.Cookie.SecurePolicy = CookieSecurePolicy.Always` in `AddSession()`
- Add `app.UseHsts()` and `app.UseHttpsRedirection()` to enforce HTTPS at the application level
- Test by proxying traffic over HTTP and confirming sensitive cookies are not transmitted
