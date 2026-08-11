# CWE-287: Improper Authentication - C#

## LLM Guidance

In ASP.NET Core, Improper Authentication commonly appears as `SignInManager.PasswordSignInAsync(..., lockoutOnFailure: false)`, which disables ASP.NET Core Identity's account lockout and allows unlimited credential-stuffing attempts against the same account. It also appears in JWT validation via `System.IdentityModel.Tokens.Jwt`/`Microsoft.IdentityModel.Tokens`, where `TokenValidationParameters` omits `ValidAlgorithms` or is given a custom `SignatureValidator` delegate that returns the token without checking its signature. Fix by enabling `lockoutOnFailure` and configuring `IdentityOptions.Lockout`, and by setting `ValidAlgorithms` explicitly while leaving the default signature validator in place.

## Key Principles

- Call `SignInManager.PasswordSignInAsync(..., lockoutOnFailure: true)` and configure `services.Configure<IdentityOptions>(o => { o.Lockout.MaxFailedAccessAttempts = 5; o.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15); })` so repeated failed logins lock the account instead of allowing unlimited attempts.
- Configure `IdentityOptions.Password` with an explicit minimum length and complexity requirement rather than accepting unreviewed framework defaults.
- Set `TokenValidationParameters.ValidAlgorithms` to the exact algorithm(s) the issuer signs with (e.g. `new[] { SecurityAlgorithms.HmacSha256 }`) so a token cannot switch to a different or weaker algorithm than intended.
- Never assign a custom `SignatureValidator` or `TokenReader` delegate that returns a token without verifying it - this fully bypasses signature checking; leave `ValidateIssuerSigningKey = true` and the built-in validator in place.
- Set `ValidateIssuer`, `ValidateAudience`, and `ValidateLifetime` to `true` with explicit `ValidIssuer`/`ValidAudience` values, not wildcard acceptance.
- Load the JWT signing key from configuration or a secret store (`IConfiguration`, Azure Key Vault), not a literal string in `TokenValidationParameters`.

## Taint Sinks

`PasswordSignInAsync(lockoutOnFailure: false)`, custom `SignatureValidator` delegate, `TokenValidationParameters` without `ValidAlgorithms`

## Remediation Steps

- Locate - Find calls to `SignInManager.PasswordSignInAsync`/`CheckPasswordSignInAsync` and `AddJwtBearer`/`TokenValidationParameters` configuration
- Trace data flow - Follow the login credential into `SignInManager`, and the bearer token from the `Authorization` header into the JWT middleware
- Replace the unsafe pattern - Change `lockoutOnFailure` to `true`; remove any custom `SignatureValidator`/`TokenReader` override that skips verification
- Bind, encode, validate, or authorize - Set `ValidAlgorithms`, `ValidIssuer`, and `ValidAudience` explicitly on `TokenValidationParameters` to match what the issuer actually produces
- Break taint after allowlist validation - Populate `ClaimsPrincipal`/`HttpContext.User` only from a token that passed full `TokenValidationParameters` validation, never from a manually parsed `JwtSecurityToken`
- Harden configuration - Review `IdentityOptions.Lockout` and `IdentityOptions.Password` in `Program.cs`/`Startup.cs` against the framework defaults
- Test - Write an integration test with 6 consecutive wrong passwords (expect lockout), and a forged token with `alg: none` or a mismatched algorithm (expect 401)

## Safe Pattern

```csharp
// SAFE: enable lockout on repeated failed sign-in attempts
var result = await signInManager.PasswordSignInAsync(
    user.UserName, password, isPersistent: false, lockoutOnFailure: true);

if (result.IsLockedOut)
{
    return Unauthorized("Account locked due to repeated failed attempts.");
}

// SAFE: pin the accepted signing algorithm(s) for JWT validation
services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(signingKeyBytes),
            ValidAlgorithms = new[] { SecurityAlgorithms.HmacSha256 },
            ValidateIssuer = true,
            ValidIssuer = "https://issuer.example.com",
            ValidateAudience = true,
            ValidAudience = "api://my-app",
            ValidateLifetime = true
        };
    });
```
