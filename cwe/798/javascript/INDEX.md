# CWE-798: Use of Hard-coded Credentials - JavaScript

## LLM Guidance

Hard-coded credentials in JavaScript/Node.js occur when sensitive values (passwords, API keys, database credentials, JWT secrets, encryption keys) are embedded directly in source code or configuration files. This exposes secrets in version control, build artifacts, and deployed code. The fix is to externalize all secrets to environment variables or secure secret management services, never committing them to repositories.

## Key Principles

- Read secrets from `process.env` or a secrets manager, and keep `.env` to local development with a `.gitignore` entry that actually matches it
- A secret reachable from client-side code is disclosed the moment the bundle ships: a key inlined by the bundler through `process.env.*` in front-end code, or one sent to the browser in a config endpoint, is public regardless of where it was loaded from
- Environment variables are a practical fallback but not risk-free - they can leak through process inspection (`/proc/<pid>/environ`), crash reports, or cloud metadata endpoints, so prefer a secrets manager in production

## Taint Sinks

`mysql.createConnection({password: "..."})`, `new AWS.Config({accessKeyId, secretAccessKey})`, `jwt.sign(payload, secret)`, `process.env.X || "literal"` fallback

## Remediation Steps

- Move all hardcoded credentials to environment variables or secret management services
- Create .env file for local development and add .env to .gitignore
- Install and configure dotenv package to load environment variables in development
- Update code to reference process.env.VARIABLE_NAME instead of hardcoded strings
- Rotate all exposed credentials and update them in secure storage systems
- Add pre-commit hooks or CI checks using tools like gitleaks or trufflehog
