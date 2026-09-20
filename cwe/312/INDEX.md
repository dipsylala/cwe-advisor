# CWE-312: Cleartext Storage of Sensitive Information

## LLM Guidance

Know which layer protects what: full-disk encryption and database TDE defend a disk, volume image, or backup medium that leaves the building, while on a running system the application, the database account, a DBA, and anyone who reaches either read plaintext exactly as before. The transmission counterpart is CWE-319, a file or disk specifically is CWE-313, and process memory is CWE-316.

## Key Principles

- Never store sensitive information in cleartext; always encrypt or redact before persisting
- Use strong encryption algorithms (AES-256) for data at rest
- Implement defence-in-depth - combine database encryption, column-level encryption, and application-level encryption
- Protect encryption keys separately from encrypted data
- Redact sensitive data from logs, cache, and temporary files
- A logical export (`mysqldump`, `pg_dump`, `bcp`) of a TDE-protected database contains plaintext, because it leaves through the SQL layer TDE decrypts for; use application- or column-level encryption for fields that must survive a dump or a compromised database credential
- Provider-managed cloud storage keys have the same shape as TDE - the service decrypts for any caller it authorizes - so where the threat is a leaked credential or an over-broad policy rather than a stolen drive, encrypt client-side before upload
- "Keys stored separately" means a different trust boundary, not a different row: a key in the same config file, database, repository, or bucket as the ciphertext is recovered by whoever recovered the data. The application should hold a credential that lets it *use* the key, ideally a workload identity rather than a static secret

## Remediation Steps

- Identify storage locations - Review flaw details to locate where sensitive data is stored (database columns, configuration files, logs, cache, temporary files, cloud storage)
- Classify data type - Determine what's exposed (credentials, API keys, PII, financial data, health records, cryptographic keys)
- Implement database encryption - Use transparent data encryption (TDE) for entire database; apply column-level encryption with AES-256 for extra-sensitive fields
- Encrypt files and configuration - Use filesystem-level or application-level encryption for sensitive configuration files and local storage
- Redact from logs - Remove or mask sensitive data before writing to logs, error messages, or debug output
- Secure encryption keys - Store keys in dedicated key management systems (AWS KMS, Azure Key Vault, HashiCorp Vault), never alongside encrypted data
