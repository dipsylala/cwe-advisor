# CWE-522: Insufficiently Protected Credentials - C#

## LLM Guidance

Insufficiently protected credentials in .NET appear as connection strings or API keys in `appsettings.json` and `web.config`, and as passwords stored with a fast digest. Separate the two cases before fixing either: a user password is hashed and never read back, while a credential the application presents to another system is loaded at runtime from a secret store. For password storage the framework already ships the answer, and it is not the one most code reaches for.

## Key Principles

- ASP.NET Core ships `PasswordHasher<TUser>` in `Microsoft.AspNetCore.Identity`, and Microsoft's guidance is explicit that it is what new code should use: "`KeyDerivation.Pbkdf2` shouldn't be used in new apps that support password-based sign in and which need to store hashed passwords in a datastore. New apps should use the `PasswordHasher` class." It encodes the parameters into the stored value and rehashes on verify when the configured iteration count has risen
- Its current format is PBKDF2 with **HMAC-SHA512, 128-bit salt, 256-bit subkey, 100,000 iterations**, set by `PasswordHasherOptions.IterationCount`. That changed in **.NET 7** - .NET 6 used HMAC-SHA256 at 10,000 - so a store written under .NET 6 rehashes on next successful sign-in rather than needing migration
- **Do not reach for `Rfc2898DeriveBytes`.** Its constructors default to HMAC-**SHA1** and 1000 iterations; five of them are obsolete from .NET 7 (`SYSLIB0041`) and from .NET 10 *all* of them are, under `SYSLIB0060`, whose message reads "The constructors on Rfc2898DeriveBytes are obsolete. Use the static Pbkdf2 method instead." The replacement is the one-shot `Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, hashAlgorithm, outputLength)` (.NET 6+), which has no defaults - both the iteration count and the hash algorithm are mandatory arguments
- If a bcrypt library is preferred, the package is `BCrypt.Net-Next` and its default work factor is **11**, not 12. Unlike most bcrypt implementations it neither enforces nor documents the 72-byte ceiling - there is no length check and no exception, and its own docs argue the limit is "less relevant", offering the `Enhanced*` SHA-prehash methods instead. Decide explicitly what a 100-byte passphrase should do
- Argon2 is not a package name. The NuGet id is `Konscious.Security.Cryptography.Argon2`; name it so a dependency check is possible
- `CA5350` ("Do Not Use Weak Cryptographic Algorithms", SHA1) and `CA5351` ("Do Not Use Broken Cryptographic Algorithms", MD5) exist but are **not enabled by default**, and neither mentions passwords - both propose plain SHA-2 as the fix, which is still wrong for password storage. Turn them on for the algorithm findings, and do not take their suggested replacement for a password answer
- On the classes themselves, only the `MD5.Create(String)` and `SHA1.Create(String)` overloads carry `[Obsolete]`; the parameterless `MD5.Create()` is not obsolete, so its absence from build warnings says nothing about whether it is being misused
- Provider order decides whether a fix takes effect. Environment variables are read after `appsettings.json` and after user secrets and so override both, and user secrets are registered automatically only in the `Development` environment. `AddUserSecrets<T>(bool optional)` exists, and with `optional: false` it throws when the assembly has no `UserSecretsIdAttribute`
- For a value that genuinely must be recovered rather than recognised, use Data Protection's `IDataProtector` from `CreateProtector(purpose)` - but note Microsoft documents it for reversible payload protection, not for password storage, and that its key ring needs its own filesystem or Key Vault protection

## Taint Sinks

`MD5.Create()`/`SHA1.Create()`/`SHA256.Create()` used as a password hash, `new Rfc2898DeriveBytes(...)` constructors, plaintext connection strings, hardcoded secrets in `appsettings.json`, `web.config` or `launchSettings.json`, a token compared with `==`

## Remediation Steps

- Separate the two cases - Hash what only needs recognising; fetch what must be presented elsewhere
- Replace the password hash - Use `PasswordHasher<TUser>` where Identity is present, or `Rfc2898DeriveBytes.Pbkdf2` with an explicit algorithm and iteration count where it is not, and rehash on successful verify
- Externalise the rest - Move connection strings and keys to Key Vault or the environment through `IConfiguration`, with User Secrets for local development only, and prefer a managed identity so there is no secret to place
- Enable the analyzers - `CA5350` and `CA5351` are off by default; turn them on rather than assuming a clean build means no weak algorithm
- Untrack, do not just ignore - Adding a settings file to `.gitignore` leaves an already-tracked file tracked; `git rm --cached` is what removes it, and neither touches history
- Rotate - Treat anything that reached version control as compromised and revoke it before or alongside the cleanup
