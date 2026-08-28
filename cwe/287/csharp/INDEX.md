# CWE-287: Improper Authentication - C#

## LLM Guidance

In ASP.NET Core, Improper Authentication commonly appears in JWT validation via `System.IdentityModel.Tokens.Jwt`/`Microsoft.IdentityModel.Tokens`, where `TokenValidationParameters` omits `ValidAlgorithms` or is given a custom `SignatureValidator` delegate that returns the token without checking its signature, and in code that reads identity from a client-supplied cookie or header instead of the `ClaimsPrincipal` the authentication middleware built. It also appears at sign-in: `SignInManager.PasswordSignInAsync(..., lockoutOnFailure: false)` disables Identity's account lockout, and the `string userName` overload answers an unknown name without hashing, timing which accounts exist. Fix by setting `ValidAlgorithms` explicitly while leaving the default signature validator in place, enabling `lockoutOnFailure`, and hashing a decoy credential when the user lookup misses.

## Key Principles

- Call `SignInManager.PasswordSignInAsync(..., lockoutOnFailure: true)` and configure `services.Configure<IdentityOptions>(o => { o.Lockout.MaxFailedAccessAttempts = 5; o.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15); })` so repeated failed logins lock the account instead of allowing unlimited attempts. The lockout *policy* - thresholds, windows, rate limiting - is CWE-307; what belongs here is the `lockoutOnFailure` flag on the authentication call itself, since passing `false` disables that policy however carefully it was configured.
- Make authentication the default for endpoints rather than something each one opts into: set `options.FallbackPolicy = new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build()` in `AddAuthorization`. The fallback policy applies to every endpoint that carries no authorization metadata, so a newly added controller action or minimal API route is protected unless it declares `[AllowAnonymous]`. `DefaultPolicy` does not do this - it only supplies the policy used by a bare `[Authorize]`
- Configure `IdentityOptions.Password` with an explicit minimum length and complexity requirement rather than accepting unreviewed framework defaults.
- Resolve the account yourself with `UserManager.FindByNameAsync` and call the `TUser` overload of `PasswordSignInAsync`: `PasswordSignInAsync(string userName, ...)` returns `SignInResult.Failed` without hashing when the name is unknown, measured at 0.003 ms against 63 ms for a wrong password.
- On that miss, spend the same cost by calling `IPasswordHasher<TUser>.VerifyHashedPassword` against a decoy hash and discarding the result. Produce the decoy at start-up from the configured hasher (a singleton calling `HashPassword`), not as a pasted literal - Identity reads the iteration count out of the stored hash, so a literal keeps costing its original count after `PasswordHasherOptions.IterationCount` is raised, and an empty or malformed string fails the format check in microseconds.
- `SignInManager` issues a brand-new authentication cookie on every successful sign-in, so cookie authentication is not fixatable on its own; if a bespoke session store (`ISession`, a session table) is layered on top, regenerate its identifier at successful sign-in, not before.
- Set `TokenValidationParameters.ValidAlgorithms` to the exact algorithm(s) the issuer signs with (e.g. `new[] { SecurityAlgorithms.HmacSha256 }`) so a token cannot switch to a different or weaker algorithm than intended.
- Never assign a custom `SignatureValidator` or `TokenReader` delegate that returns a token without verifying it - this fully bypasses signature checking; leave `ValidateIssuerSigningKey = true` and the built-in validator in place.
- Set `ValidateIssuer`, `ValidateAudience`, and `ValidateLifetime` to `true` with explicit `ValidIssuer`/`ValidAudience` values, not wildcard acceptance.
- Load the JWT signing key from configuration or a secret store (`IConfiguration`, Azure Key Vault), not a literal string in `TokenValidationParameters`.

## Taint Sinks

`PasswordSignInAsync(lockoutOnFailure: false)`, `PasswordSignInAsync(string userName, ...)`, custom `SignatureValidator` delegate, `TokenValidationParameters` without `ValidAlgorithms`

## Remediation Steps

- Locate - Find calls to `SignInManager.PasswordSignInAsync`/`CheckPasswordSignInAsync` and `AddJwtBearer`/`TokenValidationParameters` configuration
- Trace data flow - Follow the login credential into `SignInManager`, and the bearer token from the `Authorization` header into the JWT middleware
- Replace the unsafe pattern - Change `lockoutOnFailure` to `true` and branch on the returned `SignInResult.IsLockedOut` so a locked account is refused rather than retried; remove any custom `SignatureValidator`/`TokenReader` override that skips verification
- Bind, encode, validate, or authorize - Set `ValidAlgorithms`, `ValidIssuer`, and `ValidAudience` explicitly on `TokenValidationParameters` to match what the issuer actually produces
- Break taint after allowlist validation - Populate `ClaimsPrincipal`/`HttpContext.User` only from a token that passed full `TokenValidationParameters` validation, never from a manually parsed `JwtSecurityToken`
- Harden configuration - Review `IdentityOptions.Lockout` and `IdentityOptions.Password` in `Program.cs`/`Startup.cs` against the framework defaults
- Test - Write an integration test with 6 consecutive wrong passwords (expect lockout), and a forged token with `alg: none` or a mismatched algorithm (expect 401); time a right password, a wrong password, and an unknown username and assert all three are within noise of each other
