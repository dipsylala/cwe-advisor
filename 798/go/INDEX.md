# CWE-798: Use of Hard-coded Credentials - Go

## LLM Guidance

Hard-coded credentials in Go typically appear as string literals or `const`/`var` declarations for passwords, API keys, or connection strings embedded directly in `.go` files, or as real values committed inside `config.yaml`/`.env` files rather than templates. Remove the literal and load the value at runtime from `os.Getenv()`, an injected config struct, or a secrets manager SDK (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault). Check CLI tools, migration scripts, and tests in the same repository - a secrets-manager migration in `main()` is incomplete if a separate script still reads a config file with real values.

## Key Principles

- Never embed passwords, API keys, tokens, or encryption keys as string literals, `const`, or `var` declarations in `.go` source
- Load credentials via `os.Getenv()` for simple deployments, or a secrets manager SDK (`github.com/aws/aws-sdk-go-v2/service/secretsmanager`, `github.com/hashicorp/vault/api`) for production
- Do not treat a committed `config.yaml`/`.env` file as safe just because the Go code reads it dynamically - if the file with real values is tracked in git, the secret is still exposed
- Validate that required credential environment variables are non-empty at startup and fail fast with a clear error rather than proceeding with a zero value
- Never log a loaded config struct (`log.Printf("%+v", config)`) - this reintroduces exposure even when the credential source itself is secure
- Add secret-scanning tools (TruffleHog, git-secrets, GitHub secret scanning) to CI to catch reintroduced literals - `go vet` does not detect secrets, it only checks for suspicious constructs
- Environment variables are a reasonable fallback, not a risk-free store - they remain readable via `/proc/<pid>/environ`, `ps eww <pid>` on BSD-style `ps`, or cloud metadata endpoints, so prefer a secrets manager for production credentials

## Remediation Steps

- Locate - Search source, config files (`config.yaml`, `.env`), test helpers, and CLI/migration scripts for embedded credentials; check git history for previously committed values
- Trace data flow - Identify every call site that uses the hard-coded value (database driver, HTTP client, `cipher.NewCipher`, etc.) so all are updated consistently
- Replace the unsafe pattern - Remove the literal and read the value via `os.Getenv()` or a secrets manager client at startup or on first use
- Bind, encode, validate, or authorize - Add a startup check that returns a clear error if a required credential environment variable is empty
- Harden configuration - Add the real config file (`config.yaml`, `.env`) to `.gitignore` if not already ignored, and commit only a `config.yaml.example` with placeholder values
- Test - Confirm the application starts correctly with credentials supplied via environment/secrets manager and fails clearly when they are missing
- Rotate - Rotate and revoke any credential that was ever committed, since git history retains it even after removal from the working tree

## Safe Pattern

```go
import (
    "fmt"
    "os"
)

// SAFE: load credential from environment, fail fast with a clear error if missing
func requireEnv(key string) (string, error) {
    val := os.Getenv(key)
    if val == "" {
        return "", fmt.Errorf("required environment variable %s not set", key)
    }
    return val, nil
}

dbPassword, err := requireEnv("DB_PASSWORD")
```
