# CWE-798: Use of Hard-coded Credentials - JavaScript

## LLM Guidance

Hard-coded credentials in Node reach version control, build artifacts and, when the value crosses into front-end code, the browser itself. Most findings are *outbound* - a key the application sends somewhere - and the fix is to read the value at runtime. Check first whether the literal is one the application *accepts*, such as a token compared in a middleware, since that is a backdoor no secret store fixes. For the outbound case, establish whether the code runs on the server or ships to the client before choosing where to move the value, because a client-side secret cannot be fixed by relocating it.

## Key Principles

- A bundler inlines by prefix, and the prefix is the whole control. Vite exposes only `VITE_`-prefixed variables on `import.meta.env` and warns that they "should _not_ contain sensitive information such as API keys"; Next.js inlines only `NEXT_PUBLIC_`-prefixed ones, replacing `process.env.NAME` with the literal at build time. A secret behind either prefix is published by `build`, so grep the prefixes rather than the variable names
- Next.js inlines only static references: `process.env[varName]` and destructuring through an intermediate `const env = process.env` are not replaced, so a value that appears absent in the bundle may simply have failed to inline
- Node loads `.env` itself now - `node --env-file=.env`, stable since 22.21.0 and 24.10.0, with `--env-file-if-exists` for an optional file and the still-experimental `process.loadEnvFile()`. Adding `dotenv` to a current runtime is often an unnecessary dependency; note that dotenv's own README now steers encryption work to the separate `dotenvx` package
- Environment variables are a fallback rather than a store, but state the exposure accurately: `/proc/<pid>/environ` is governed by a `PTRACE_MODE_READ_FSCREDS` check, so it is readable by the same user or by a process holding `CAP_SYS_PTRACE`, not by any local account. The realistic paths are a compromised process running as that user, a crash report, or a platform metadata endpoint
- Name the client package so the version can be checked: `@aws-sdk/client-secrets-manager`, `@azure/keyvault-secrets`, or `@google-cloud/secret-manager`
- Floor `jsonwebtoken` at **9.0.0**, which closed three advisories in `jwt.verify` including an insecure default algorithm permitting signature-validation bypass (CVE-2022-23540) and an RSA-to-HMAC key confusion (CVE-2022-23541). Latest is 9.0.3, so floor and latest differ
- Pre-commit and CI are one layer; GitHub's own push protection is another, and its defaults are easy to misread - repository-level protection is off by default and needs GitHub Secret Protection, while user-level protection is on by default but only blocks pushes to *public* repositories
- `gitleaks` is MIT and `trufflehog` is AGPL-3.0 with a paid enterprise tier, which is a real difference when the scanner is vendored into a build rather than run as a hosted action

## Taint Sinks

`mysql.createConnection({password: "..."})` or the same call in `mysql2`, `jwt.sign(payload, secret)`, `new AWS.Config({accessKeyId, secretAccessKey})`, `process.env.X || "literal"` fallback, a literal compared in an auth middleware, real values in a committed `Dockerfile` `ENV` line or Kubernetes manifest

## Remediation Steps

- Locate - Search source, `.env` files, `Dockerfile` `ENV` lines, Compose files and Kubernetes manifests; a value moved out of code into a committed manifest is the same finding one file over
- Confirm the direction and the runtime - A literal compared against user input needs deletion rather than a secret store; a literal in code that ships to the browser is already public and needs the call moved server-side
- Rotate first - The credential is in history and in any published bundle, so revoke before refactoring
- Replace the read - Use `process.env` fed by `--env-file` or the platform, or a named secrets-manager client; for AWS, note that `aws-sdk` v2 reached end of support in September 2025 and is marked deprecated on npm, so the v3 equivalent is a `@aws-sdk/*` client with a provider such as `fromEnv()` or `fromIni()` rather than `new AWS.Config`
- Untrack, do not just ignore - Adding `.env` to `.gitignore` leaves an already-tracked file tracked; `git rm --cached .env` is what removes it, and neither touches history
- Check the fallback - `process.env.SECRET || "literal"` reintroduces the credential precisely when the environment is not configured, which is the case in every fresh checkout
- Test - Confirm the app starts with the value supplied externally and fails clearly when absent, and grep the production bundle for the secret to prove it did not inline
