# CWE-798: Use of Hard-coded Credentials - C#

## LLM Guidance

Hard-coded credentials in C# reach version control and compiled assemblies alike. Most findings are *outbound* - a password, key or connection string the application sends somewhere - and the fix is to fetch the value at runtime. Check first whether the literal is instead one the application *accepts*, such as a comparison in a sign-in path, because that is a backdoor no secret store fixes. For the outbound case prefer an identity over a secret: on Azure a managed identity removes the credential rather than relocating it.

## Key Principles

- User Secrets are for development only and Microsoft is explicit that they are not a vault: "Secret Manager doesn't encrypt the stored secrets and shouldn't be treated as a trusted store." They are plain JSON under `%APPDATA%\Microsoft\UserSecrets\<id>\secrets.json` or `~/.microsoft/usersecrets/<id>/secrets.json`, linked by the `UserSecretsId` element in the project file
- `DefaultAzureCredential` is not a workload identity - it is an ordered chain that tries environment variables, workload identity, managed identity, then local developer tooling. Microsoft's own guidance is to replace it once deployed: "replace `DefaultAzureCredential` with a specific `TokenCredential` implementation, such as `ManagedIdentityCredential`", because which link succeeds cannot be predicted. Use it to get started, name the credential in production
- Floor `Azure.Identity` at **1.11.4**: 1.10.2 fixed a remote code execution (CVE-2023-36414), 1.11.0 an information disclosure (CVE-2024-29992), and 1.11.4 an elevation of privilege (CVE-2024-35255) that also floors `Microsoft.Identity.Client` at 4.60.4 / 4.61.3
- For SQL the fix that removes the secret is a connection-string option, not a relocation: `Authentication=Active Directory Default` or `Active Directory Managed Identity` needs no password at all. From `Microsoft.Data.SqlClient` 7.0 those modes require the separate `Microsoft.Data.SqlClient.Extensions.Azure` package, so adding the option alone breaks the build's authentication path there. `Active Directory Password` is obsolete and warns at compile time
- Prefer `Microsoft.Data.SqlClient` over `System.Data.SqlClient`, whose own NuGet listing states it is deprecated; the supported floor is 6.1 (LTS) with 7.0 current. Both packages carried CVE-2024-0056, fixed in 5.1.3 / 4.0.5 / 3.1.5 / 2.1.7 and in `System.Data.SqlClient` 4.8.6
- Provider order decides whether the fix takes effect: environment variables are read after `appsettings.json` and after user secrets, so they override both, and a provider added after the defaults outranks them. User secrets are registered automatically only when the environment is `Development`
- `CA5390` ("Do not hard-code encryption key") ships with the analyzers but is **not enabled by default**, so turn it on rather than assuming the build would have caught the key
- `SecureString` is not the remediation. Microsoft advises against it for new development and it does not encrypt its storage off Windows; the recommended shape is an opaque handle to a credential held outside the process
- Grant the vault identity `get`/`list` only - an application that can also `set` or `delete` secrets has a far larger blast radius than one that can read the two it needs

## Taint Sinks

`new SqlConnection(connectionString)` with a literal password, `new NetworkCredential(user, password)`, `UseSqlServer(connectionString)`, `new SqlConnectionStringBuilder { Password = ... }`, literal values in `appsettings.json`, `launchSettings.json` or a committed Compose file, a literal compared in a sign-in path

## Remediation Steps

- Locate - Search source, `appsettings*.json`, `web.config`, `launchSettings.json`, Compose files and deployment manifests; a value moved from a `const` into a committed config file is the same finding one file over
- Confirm the direction - If the literal is compared against user input rather than sent to a service, no secret store applies: remove the credential and replace it with per-installation enrolment
- Rotate first - The credential is already published in history and in any built artifact, so revoke before refactoring
- Apply the fix - Prefer removing the secret outright with a managed identity and `Authentication=Active Directory Default`; otherwise read it through `IConfiguration` from Key Vault (`AddAzureKeyVault` with `Azure.Extensions.AspNetCore.Configuration.Secrets`), with User Secrets for local development only
- Check the fallback path - A correct Key Vault call with an `Environment.GetEnvironmentVariable` fallback whose value sits in a committed `launchSettings.json` reintroduces exactly what was removed
- Untrack, do not just ignore - Adding a config file to `.gitignore` leaves an already-tracked file tracked; `git rm --cached` is what removes it, and neither touches history
- Test - Confirm the application starts with the secret supplied by the store and fails clearly when it is absent, and that no secret appears in the built assembly
