# CWE-352: Cross-Site Request Forgery (CSRF) - C#

## LLM Guidance

CSRF vulnerabilities occur when state-changing endpoints don't verify requests originated from the application itself, allowing attackers to perform actions on behalf of authenticated users. ASP.NET Core provides built-in anti-forgery token support that should be enabled on all state-changing operations.

**Primary Defence:** Use `[ValidateAntiForgeryToken]` attribute on POST/PUT/DELETE actions or enabling automatic validation globally.

## Key Principles

- Apply anti-forgery tokens to all state-changing HTTP methods (POST, PUT, DELETE, PATCH)
- Use automatic token validation globally rather than relying on per-action attributes
- Ensure tokens are included in forms via `@Html.AntiForgeryToken()` or auto-generated
- Validate SameSite cookie attributes are set to `Strict` or `Lax`
- Never disable CSRF protection for authenticated endpoints
- Use the framework's `IAntiforgery` service rather than a hand-rolled token: it generates with `RandomNumberGenerator` and binds the `__RequestVerificationToken` to the authenticated user; the per-user claim check compares in constant time with `CryptographicOperations.FixedTimeEquals`, while the primary cookie-vs-request token match uses a separate hand-rolled constant-time comparison internal to the framework
- API endpoints that accept JSON still need the check - a token in a header is the usual form, since a cookie alone is not proof of intent. `AntiforgeryOptions.HeaderName` already defaults to `RequestVerificationToken` (no leading `X-`), so a client sending that exact header name works with no configuration change; a client sending a different name such as `X-CSRF-TOKEN` fails validation until `HeaderName` is set to match it in `AddAntiforgery`
- `AutoValidateAntiforgeryTokenAttribute` and `[ValidateAntiForgeryToken]` are MVC filters and never run for a minimal API endpoint. Minimal APIs are covered instead by `app.UseAntiforgery()` in the middleware pipeline, placed after authentication and authorization and before the endpoints - so an application that moved controller actions to minimal APIs loses its CSRF protection silently unless that call was added

## Taint Sinks

`[HttpPost]`/`[HttpPut]`/`[HttpDelete]` actions missing `[ValidateAntiForgeryToken]`, `[IgnoreAntiforgeryToken]`

## Remediation Steps

- Add `services.AddAntiforgery()` to `ConfigureServices` in Startup.cs
- Enable automatic validation for MVC with `options.Filters.Add(new AutoValidateAntiforgeryTokenAttribute())`, and add `app.UseAntiforgery()` for any minimal API endpoints, which the filter does not reach
- Add `@Html.AntiForgeryToken()` to all forms or use Tag Helpers with `method="post"`
- Apply `[ValidateAntiForgeryToken]` to individual controllers/actions if not using global filters
- Confirm SameSite on the antiforgery cookie - `CookieBuilder.SameSite` already defaults to `SameSiteMode.Strict`; only relax it to `Lax` if an inbound link, SSO redirect, or OAuth callback needs the cookie present
- Test protected endpoints reject requests without valid tokens
