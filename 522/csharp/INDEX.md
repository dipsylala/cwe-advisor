# CWE-522: Insufficiently Protected Credentials - C# / .NET

## LLM Guidance

Insufficiently protected credentials in C# typically manifest as connection strings or API keys embedded in `appsettings.json`, hardcoded in source code, or stored in `web.config` in plaintext. In ASP.NET Core, credentials should be loaded from environment variables, the .NET Secret Manager (development), or a secrets vault (production) — never from files committed to version control. Passwords stored in databases must be hashed with `BCrypt.Net`, `Argon2`, or `PBKDF2` via `Rfc2898DeriveBytes`.

## Key Principles

- Store secrets in environment variables, Azure Key Vault, AWS Secrets Manager, or .NET Secret Manager — not in `appsettings.json` committed to source control
- Hash passwords with `BCrypt.Net-Next` or `Argon2` before storage; never store plaintext or use reversible encryption
- Use `IConfiguration` to read secrets so the source can be swapped between environments without code changes
- Add `appsettings*.json` overrides with secrets to `.gitignore`; use `dotnet user-secrets` in development
- Rotate any secrets that have been committed to version control and treat them as compromised

## Remediation Steps

- Remove hardcoded credentials and connection strings from source code and `appsettings.json`
- Initialize `dotnet user-secrets init` and store development secrets with `dotnet user-secrets set "Key" "Value"`
- In production, bind secrets via environment variables or a vault provider in `Program.cs`
- Replace plaintext password storage with `BCrypt.Net.BCrypt.HashPassword(password, workFactor: 12)`
- Verify passwords with `BCrypt.Net.BCrypt.Verify(plainPassword, storedHash)`
- Scan commit history for leaked secrets and rotate them immediately

## Safe Pattern

```csharp
// Program.cs — load secrets from environment / vault
builder.Configuration
    .AddEnvironmentVariables()           // Reads DATABASE_URL, API_KEY, etc.
    .AddUserSecrets<Program>(optional: true); // Development only

// Inject and use via IConfiguration — no hardcoding
public class MyService(IConfiguration config)
{
    private readonly string _connectionString = config.GetConnectionString("Default")
        ?? throw new InvalidOperationException("Connection string not configured");
}

// Password hashing with BCrypt
using BCrypt.Net;

public static string HashPassword(string plainPassword)
    => BCrypt.HashPassword(plainPassword, workFactor: 12);

public static bool VerifyPassword(string plainPassword, string hash)
    => BCrypt.Verify(plainPassword, hash);
```
