# CWE-522: Insufficiently Protected Credentials - Java

## LLM Guidance

Insufficiently Protected Credentials in Java occurs when passwords, API keys, or authentication tokens are hardcoded, stored in plaintext, weakly encrypted, or transmitted insecurely. The core fix is to externalize credentials to secure vaults (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault), use environment variables or encrypted configuration files, and leverage Java's KeyStore or strong encryption (AES-256) when storage is necessary. Never log, hardcode, or commit credentials to version control.

## Key Principles

- Store credentials in external secret management systems (AWS Secrets Manager, Azure Key Vault, HashiCorp Vault)
- Use environment variables or encrypted configuration files with restricted file permissions
- Encrypt credentials at rest using a secrets manager/KMS, platform-backed storage, or PKCS12 KeyStore when local storage is unavoidable; never store plaintext passwords
- Hash user passwords with `BCryptPasswordEncoder` (Spring Security) or Argon2 (`argon2-jvm`); never encrypt passwords reversibly or store them in plaintext
- Transmit credentials only over TLS/SSL; use char[] for passwords in memory and clear immediately after use
- Implement credential rotation policies and audit access logs regularly

## Remediation Steps

- Remove hardcoded credentials from source code; scan with tools like git-secrets or TruffleHog
- Migrate credentials to AWS Secrets Manager, Azure Key Vault, or HashiCorp Vault
- Configure application to retrieve credentials at runtime from secret manager or environment variables
- Use PKCS12 KeyStore or platform-backed storage for local encrypted credential storage if a secrets manager is not available
- Hash user passwords with `BCryptPasswordEncoder` or Argon2 before storage; verify with the same encoder's `matches()`/`verify()` method, never a manual comparison
- Replace String passwords with char[] and zero out arrays after authentication
- Enable TLS 1.3 for all credential transmission; never send credentials in URLs or logs

## Safe Pattern

```java
// Retrieve credentials from AWS Secrets Manager (AWS SDK for Java v2 -
// v1's com.amazonaws.services.secretsmanager reached end-of-support Dec 2025)
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;

SecretsManagerClient client = SecretsManagerClient.builder()
    .region(Region.US_EAST_1).build();

GetSecretValueRequest request = GetSecretValueRequest.builder()
    .secretId("prod/db/password").build();
GetSecretValueResponse result = client.getSecretValue(request);
String secret = result.secretString();

// Use credential immediately; avoid claiming full clearing after creating a String copy
char[] password = secret.toCharArray();
authenticateUser(username, password);
Arrays.fill(password, '\0'); // Clear sensitive data
```
