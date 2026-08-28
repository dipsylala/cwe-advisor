# CWE-798: Use of Hard-coded Credentials - Java

## LLM Guidance

Hard-coded credentials in source code are exposed in version control, decompiled bytecode, and configuration files. Attackers gaining access to the codebase can extract these credentials to compromise systems. Store credentials externally using environment variables, secrets management services (AWS Secrets Manager, Azure Key Vault), or encrypted configuration files with restricted access.

## Key Principles

- Inject credentials at runtime from a secrets manager (AWS Secrets Manager, Azure Key Vault, HashiCorp Vault), or from the environment or system properties where no manager is available
- Environment variables are a reasonable fallback but not immune to leakage - they can be read via process inspection, crash dumps, or cloud metadata services, so prefer a secrets manager for production
- `application.properties` with `${DB_PASSWORD}`-style placeholders resolves from the environment, which is the right shape - but a committed `.env` or a profile-specific properties file holding the literal defeats it
- Check the built artifact as well as the source: a value bound at build time is inside the JAR and is recoverable from it

## Taint Sinks

`DriverManager.getConnection()` with literal password, `new PasswordAuthentication()`, `Properties.setProperty("password", ...)`, `@Value("${secret:default}")` hardcoded default

## Remediation Steps

- Identify all hard-coded credentials using static analysis tools or code review
- Move credentials to environment variables or a secrets management service
- Update code to retrieve credentials at runtime from external sources
- Add credential files to .gitignore to prevent accidental commits
- Remove credential history from version control using tools like git-filter-repo
- Rotate all exposed credentials immediately after removal
