# CWE-798: Use of Hard-coded Credentials - Python

## LLM Guidance

Hard-coded credentials (passwords, API keys, database credentials, encryption keys) in Python source code create security vulnerabilities by exposing secrets in version control and making rotation impossible. Always externalize credentials using environment variables, configuration files outside version control, or dedicated secrets managers. For production systems, use cloud-native solutions like AWS Secrets Manager or Azure Key Vault.

## Key Principles

- Never commit credentials to version control; use `.gitignore` for local config files
- Separate configuration from code using environment variables or external config files
- Use secrets managers for production deployments with automatic rotation
- Apply principle of least privilege to all credentials
- Implement secure defaults and fail securely when credentials are missing
- Environment variables are a practical fallback but can still leak via process inspection (`/proc/<pid>/environ`), crash dumps, or cloud metadata endpoints, so prefer a secrets manager where available
- `os.environ.get('SECRET')` is the right read; the finding is usually the `config.py` or committed `.env` that puts the literal there
- Build connection strings with a helper that takes the secret as a parameter (SQLAlchemy's `URL.create`) rather than formatting it into a URL, which then appears in logs and exception messages

## Taint Sinks

`psycopg2.connect(password=...)` with literal, hardcoded module-level `PASSWORD = "..."`, `boto3.client(aws_secret_access_key=...)`, `requests.auth.HTTPBasicAuth()`

## Remediation Steps

- Identify all hard-coded credentials in source code using grep/scanning tools
- Replace hard-coded values with `os.getenv()` calls with no defaults for secrets
- Store credentials in environment variables or `.env` files loaded with `python-dotenv`'s `load_dotenv()` (add `.env` to `.gitignore`)
- For production, migrate to secrets managers (AWS Secrets Manager, Azure Key Vault, HashiCorp Vault)
- Rotate all exposed credentials immediately
- Implement validation to ensure required credentials are present at startup
