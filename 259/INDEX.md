# CWE-259: Use of Hard-coded Password

## LLM Guidance

Hard-coded passwords embed credentials directly in source code, configuration files, or binaries, exposing secrets to anyone with codebase access. Attackers can easily extract these credentials to gain unauthorized access.

## Key Principles

- Never embed secrets in application artifacts (source, images, configs, or client code)
- Inject secrets at runtime from dedicated secrets management systems
- Treat credentials as replaceable with least-privilege access controls
- Remove secrets from version control including commit history
- Use environment variables or secret stores (AWS Secrets Manager, Azure Key Vault, HashiCorp Vault)
- A `DEFAULT_PASSWORD` constant used when nothing else is configured is the same hard-coded password with a different name
- Obfuscation is not externalization: Base64, an XOR, or concatenated fragments defeat a plain grep and remain just as recoverable once decoded
- Check the outbound uses, not only the login form: a background job, legacy integration, or service-to-service call embedding its own credential is a distinct manifestation MITRE treats separately
- A "temporary" debug or backdoor account ships when nothing tracks its removal - if one is added, the removal needs a ticket, not an intention
- The full secrets-management path (secrets store integration, rotation, history cleanup, detection tooling) is CWE-798; this entry is the password-specific case, and CWE-321 is the same problem for a cryptographic key

## Remediation Steps

- Locate hard-coded credentials - Search codebase for `password=`, `api_key=`, `secret=` patterns; check configuration files and version control history
- Delete embedded secrets - Remove password literals, constants, and hardcoded credentials from all source files
- Implement secrets management - Configure external secret store (environment variables, vault service, or cloud provider secrets manager)
- Update code to retrieve secrets - Modify application to fetch credentials at runtime from the secrets store
- Rotate compromised credentials - Change all exposed passwords immediately after removal
- Clean version control - Use tools like `git filter-branch` or BFG Repo-Cleaner to purge secrets from Git history
