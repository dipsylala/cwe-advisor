# CWE-613: Insufficient Session Expiration - C#

## LLM Guidance

The two places this shows up in ASP.NET Core are the authentication cookie and a hand-issued JWT. `CookieAuthenticationOptions.ExpireTimeSpan` defaults to 14 days with `SlidingExpiration` true, so a continuously-active cookie can outlive discovery of a compromise indefinitely unless `AuthenticationProperties.ExpiresUtc` sets a real absolute cap. A JWT built with `JwtSecurityTokenHandler.CreateToken()` is not unbounded when `SecurityTokenDescriptor.Expires` is omitted - the handler silently applies a 10-hour default - but that silent default is itself usually too long for a bearer token nobody explicitly reasoned about, and once issued nothing server-side can shorten it. Prefer .NET 8's built-in `MapIdentityApi()` token endpoints, whose short-lived-access-plus-refresh-token pattern and `BearerTokenOptions` give an explicit, first-party lifetime to configure, over hand-rolling one.

## Key Principles

- Set `AuthenticationProperties.ExpiresUtc` explicitly at sign-in for an absolute cap; `CookieAuthenticationOptions.ExpireTimeSpan`'s 14-day default combined with `SlidingExpiration = true` (also default) means a continuously-active session has no ceiling of its own
- Do not assume omitting `SecurityTokenDescriptor.Expires` on `JwtSecurityTokenHandler.CreateToken()` produces an unbounded token - `SetDefaultTimesOnTokenCreation` is on by default and silently applies `TokenLifetimeInMinutes` (600, i.e. 10 hours) instead. That silent default is usually the finding, not a lack of expiration
- `TokenValidationParameters.ValidateLifetime` and `RequireExpirationTime` both default to `true`, so a codebase that explicitly sets either to `false` has disabled a check that was already protecting it - treat that as the sharper finding than a missing configuration
- .NET has no built-in JWT denylist. For revocation before a hand-issued JWT's `exp`, either keep the token short-lived and re-issue through a refresh flow, or maintain a `jti`-keyed revocation store checked in `JwtBearerEvents.OnTokenValidated`
- Prefer `MapIdentityApi()` (.NET 8+) for new work: its issued tokens are not JWTs by design, and `BearerTokenOptions.BearerTokenExpiration`/`RefreshTokenExpiration` give an explicit, framework-owned lifetime instead of one assembled by hand
- `SessionOptions.IdleTimeout` (default 20 minutes) governs only the session *content* in `IDistributedCache`, sliding on each access - it says nothing about the authentication cookie's own lifetime, so check both independently rather than assuming one bounds the other

## Taint Sinks

`JwtSecurityTokenHandler.CreateToken()` without `SecurityTokenDescriptor.Expires` deliberately set, `TokenValidationParameters.ValidateLifetime = false`, `CookieAuthenticationOptions.ExpireTimeSpan` set to an excessive duration, `SessionOptions.IdleTimeout` set excessively long, a JWT verification path with no corresponding revocation check

## Remediation Steps

- Locate - find `JwtSecurityTokenHandler.CreateToken`/`SecurityTokenDescriptor` construction, `AddCookie`/`CookieAuthenticationOptions` configuration, and `AddSession`/`SessionOptions` configuration
- Trace what the session or token authorizes, to size the lifetime to the risk rather than copying a default
- Identify the unsafe pattern - `Expires` left to the silent 10-hour default without anyone having chosen it, `ExpireTimeSpan` set far longer than the access needs, or `ValidateLifetime`/`RequireExpirationTime` explicitly disabled
- Replace with an explicit `Expires`/`ExpiresUtc` sized to the risk, and re-enable lifetime validation if it was turned off
- Bind, encode, validate, or authorize - for pre-expiry revocation, add a `jti`-keyed store checked in `OnTokenValidated`, or move to `MapIdentityApi()`'s short-lived-access-plus-refresh pattern
- Harden configuration - keep `SlidingExpiration` paired with an explicit `ExpiresUtc` absolute cap, not relied on alone
- Test - confirm a token issued before the fix is rejected once its new, shorter expiration passes, and that a revoked token is rejected on the next request rather than only on the next issuance
