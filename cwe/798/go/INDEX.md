# CWE-798: Use of Hard-coded Credentials - Go

## LLM Guidance

Hard-coded credentials in Go appear as string literals or `const`/`var` declarations in `.go` files, or as real values in a committed `config.yaml`/`.env` rather than a template. Most findings are *outbound* - a value the program sends to a database or API - and the fix is to load it at runtime. Check first whether the literal is one the program *accepts*, such as a password compared in a handler, because that is a backdoor no secrets manager fixes. Check the build as well as the source: Go has two documented paths that put a value inside the binary without it ever appearing as a literal in the package.

## Key Principles

- Load credentials from `os.LookupEnv`, not `os.Getenv`, wherever absence must be an error: `Getenv` returns `""` for both unset and empty, and the stdlib itself says "To distinguish between an empty value and an unset value, use `LookupEnv`". That is what makes the startup check meaningful
- For production use a secrets manager SDK - `github.com/aws/aws-sdk-go-v2/service/secretsmanager` or `github.com/hashicorp/vault/api`. Stay on `vault/api`: the newer `hashicorp/vault-client-go` is still BETA and its README says "Please do not use it in production"
- `//go:embed` is a build-time path `.gitignore` never covers - an untracked `config.yaml` sitting in the package directory is still embeddable into the binary. Dotfiles are excluded by a bare directory pattern but *included* when the pattern carries the `all:` prefix, so `//go:embed all:config` picks up a `.env` the developer believed was ignored
- Injecting a credential with `-ldflags "-X main.apiKey=..."` publishes it twice over: the value lands in the binary, and the whole `-ldflags` string is recorded as a build setting that `go version -m` prints back from the shipped artifact unless `-trimpath` was passed
- Rather than only forbidding `log.Printf("%+v", config)`, give the secret its own type with a `String() string` that redacts. `%+v` is `%v` without `#`, so `fmt` invokes `Stringer`, and formatting applies to a struct's fields recursively - so the field redacts itself wherever the struct is printed. `fmt.Formatter` takes precedence over `Stringer` if every verb needs controlling
- State the environment-variable exposure accurately: `/proc/<pid>/environ` is governed by a `PTRACE_MODE_READ_FSCREDS` check, so it is readable by the same user or a caller holding `CAP_SYS_PTRACE`, not by any local account, and `ps eww` is available on Linux procps as well as BSD. The realistic paths are a compromised same-uid process, a core dump, a metadata endpoint, and - concretely - `docker inspect`, which Docker's own reference names as where `ENV` values can be viewed. The environment is also inherited by every child process the program spawns
- `net/smtp` is frozen - the package doc states it "is not accepting new features" - and `smtp.PlainAuth` refuses to send credentials at all unless the connection has TLS or the host is localhost, failing with `unencrypted connection`. Moving the password to an environment variable does not change that gate, so do not read the resulting error as a broken remediation
- `go vet` has no credential or entropy analyzer; its documented remit is "suspicious constructs". GitHub secret scanning is a platform feature rather than a CI step, free on public repositories and requiring GitHub Secret Protection for private or internal ones. `awslabs/git-secrets` is unarchived and still receiving occasional commits, but its most recent tag, 1.3.0, dates from 2019

## Taint Sinks

Hardcoded `const`/`var` string literals for passwords or keys, `sql.Open()`, `smtp.PlainAuth()`, `(*http.Request).SetBasicAuth` - grep `.SetBasicAuth(`, since there is no package-level `http.SetBasicAuth` - `url.UserPassword()`, a literal compared in a handler, real values in a committed `config.yaml`, `.env`, `Dockerfile` `ENV` line or Kubernetes manifest

## Remediation Steps

- Locate - Search source, config files, `//go:embed` directives, build scripts and CI definitions for `-ldflags -X`, plus deployment manifests; check history for values already committed
- Confirm the direction - A literal compared against caller input needs deletion and per-installation enrolment rather than a secrets manager
- Rotate first - The credential is in history and in every built artifact, so revoke before editing
- Replace the read - Load via `os.LookupEnv` or a secrets-manager client at startup, and return a clear error when the value is absent rather than proceeding with `""`
- Untrack, do not just ignore - Adding `config.yaml` to `.gitignore` leaves an already-tracked file tracked; `git rm --cached config.yaml` is what removes it, and neither touches history. Commit `config.yaml.example` with placeholders
- Redact at the type - Give credential fields a type whose `String()` masks, so a later `%+v` cannot undo the fix
- Test - Confirm the program starts with the value supplied externally and fails clearly without it, and run `go version -m` on the built binary to check no credential was recorded as a build setting
