# CWE-377: Insecure Temporary File

## LLM Guidance

Insecure temporary files occur when applications create predictable filenames, use insecure permissions (world-readable/writable), or create files in shared directories without protection. This enables information disclosure, data tampering, and symlink attacks where attackers can predict file locations and exploit race conditions.

## Key Principles

- Use platform-native secure APIs that generate cryptographically random filenames
- Create files with exclusive access (O_EXCL flag) and restrictive permissions (0600)
- Avoid shared directories like /tmp when possible; use user-specific temp directories
- Always delete temporary files after use; use auto-cleanup mechanisms where available
- Never use predictable patterns (timestamps, PIDs, sequential numbers) in filenames
- Apply the mode at creation rather than afterwards: a `chmod` after the fact leaves a window in which the file exists at the umask default, and on some platforms the temp API already applies 0600
- What the platform temp APIs actually guarantee is that the name is generated and the file claimed in *one* operation - that is the part which closes the race, not the name's quality
- Do not treat a temp filename as a secret: OpenJDK's comes from `SecureRandom`, but Go's comes from the runtime's general-purpose generator, Python's from `random.Random`, and C `mkstemp()` names vary by libc

## Remediation Steps

- Identify the vulnerability - Review flaw details for file path, line number, and insecurity type (predictable name, weak permissions, shared directory, or missing cleanup)
- Replace with secure APIs - use the language's dedicated secure temporary-file API, which generates a random name and sets safe permissions atomically, with auto-delete enabled (see the language-specific guidance's Remediation Steps for concrete APIs)
- Set restrictive permissions - Ensure mode 0600 (owner read/write only) at creation time, not after
- Implement guaranteed cleanup - Use try-finally blocks, context managers, or defer statements to ensure deletion even on errors
- Validate sensitive data handling - If temp files contain credentials or PII, consider in-memory alternatives or encrypted temporary storage
- Test the fix - Verify file permissions with `ls -l`, check filename randomness, and confirm proper cleanup under normal and error conditions
