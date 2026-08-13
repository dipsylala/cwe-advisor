# CWE-377: Insecure Temporary File

## LLM Guidance

Insecure temporary files occur when applications create predictable filenames, use insecure permissions (world-readable/writable), or create files in shared directories without protection. This enables information disclosure, data tampering, and symlink attacks where attackers can predict file locations and exploit race conditions.

## Key Principles

- Use platform-native secure APIs that generate cryptographically random filenames
- Create files with exclusive access (O_EXCL flag) and restrictive permissions (0600)
- Avoid shared directories like /tmp when possible; use user-specific temp directories
- Always delete temporary files after use; use auto-cleanup mechanisms where available
- Never use predictable patterns (timestamps, PIDs, sequential numbers) in filenames

## Remediation Steps

- Identify the vulnerability - Review flaw details for file path, line number, and insecurity type (predictable name, weak permissions, shared directory, or missing cleanup)
- Replace with secure APIs - use the language's dedicated secure temporary-file API, which generates a random name and sets safe permissions atomically, with auto-delete enabled (see the language-specific guidance's Safe Pattern for concrete APIs)
- Set restrictive permissions - Ensure mode 0600 (owner read/write only) at creation time, not after
- Implement guaranteed cleanup - Use try-finally blocks, context managers, or defer statements to ensure deletion even on errors
- Validate sensitive data handling - If temp files contain credentials or PII, consider in-memory alternatives or encrypted temporary storage
- Test the fix - Verify file permissions with `ls -l`, check filename randomness, and confirm proper cleanup under normal and error conditions
