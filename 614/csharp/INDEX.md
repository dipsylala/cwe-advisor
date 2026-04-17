# CWE-614: Sensitive Cookie Without 'Secure' Flag - C# / ASP.NET Core

## LLM Guidance

In ASP.NET Core, cookies created without `CookieOptions.Secure = true` can be transmitted over plaintext HTTP connections, exposing session tokens and authentication cookies to network interception. Set the `Secure` flag on all sensitive cookies, configure global cookie policy via `services.Configure<CookiePolicyOptions>()`, and enforce HTTPS site-wide with HSTS.

## Key Principles

- Set `Secure = true` on every `CookieOptions` used with `Response.Cookies.Append()`
- Configure `CookiePolicyOptions.Secure = CookieSecurePolicy.Always` globally to enforce the flag on all cookies
- Use ASP.NET Core's built-in session and authentication cookie configuration (both have `SecurePolicy` settings)
- Combine with `HttpOnly = true` and `SameSite = SameSiteMode.Strict` for defence-in-depth
- Enable HSTS (`UseHsts()`) so browsers only connect over HTTPS

## Remediation Steps

- Find all `Response.Cookies.Append()` calls and add `Secure = true` to their `CookieOptions`
- In `Program.cs`, add `app.UseCookiePolicy()` and configure `services.Configure<CookiePolicyOptions>(o => o.Secure = CookieSecurePolicy.Always)`
- For authentication cookies, set `options.Cookie.SecurePolicy = CookieSecurePolicy.Always` in `AddCookie()` or `AddJwtBearer()` configuration
- For session cookies, configure `options.Cookie.SecurePolicy = CookieSecurePolicy.Always` in `AddSession()`
- Add `app.UseHsts()` and `app.UseHttpsRedirection()` to enforce HTTPS at the application level
- Test by proxying traffic over HTTP and confirming sensitive cookies are not transmitted

## Safe Pattern

```csharp
// Program.cs
builder.Services.Configure<CookiePolicyOptions>(options =>
{
    options.Secure = CookieSecurePolicy.Always;
    options.HttpOnly = Microsoft.AspNetCore.CookiePolicy.HttpOnlyPolicy.Always;
});

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.HttpOnly = true;
        options.Cookie.SameSite = SameSiteMode.Strict;
    });

// Explicit cookie creation
Response.Cookies.Append("pref", value, new CookieOptions
{
    Secure   = true,
    HttpOnly = true,
    SameSite = SameSiteMode.Strict,
});
```
