# CWE-798: Use of Hard-coded Credentials - PHP

## LLM Guidance

Hard-coded credentials (passwords, API keys, database credentials, encryption keys) in PHP code or configuration files create security vulnerabilities. The core fix is to externalize all secrets using environment variables, secure configuration files outside version control, or dedicated secrets managers. Use `getenv()`, `$_ENV`, vlucas/phpdotenv for development, or cloud secrets managers for production.

## Key Principles

- Read secrets from the environment (`getenv()`, or the framework's `env()` helper used only inside cached config), keeping distinct credentials per environment
- Environment variables reduce exposure versus hard-coding but are not foolproof - they can still leak through process inspection, debug output, or misconfigured server status pages
- A `config.php` holding literals is still hard-coded even when it is not the application code: read from the environment through `config()`/`getenv()`, keep the file out of version control, and confirm it is not served (below the document root, or denied in the `VirtualHost`/`.htaccess`)
- A `.env` deployed inside the web root is fetchable by name whether or not directory listing is on

## Taint Sinks

`new PDO($dsn, $user, $password)` with literal, `define('DB_PASSWORD', ...)`, `curl_setopt($ch, CURLOPT_USERPWD, ...)`

## Remediation Steps

- Identify all hard-coded credentials in code and configuration files
- Create environment variables or use a secrets manager for each credential
- Replace hard-coded values with `getenv()` or `$_ENV` calls
- Add .env files to .gitignore and remove any committed secrets from git history
- Test credential loading in all environments
- Document the secrets management approach for the team
