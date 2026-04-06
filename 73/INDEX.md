# CWE-73: External Control of File Name or Path

## LLM Guidance

This vulnerability occurs when user input is used to construct file or directory names, allowing attackers to read, write, or delete arbitrary files on the system. Attackers can exploit path traversal (e.g., `../../../etc/passwd`) or absolute paths to access sensitive files outside intended directories.

## Key Principles

- Never use untrusted data directly as file names or path components
- Decode fully before filtering: URL-decode input (including double-encoded variants such as `%252e`) and apply Unicode NFC normalisation before any character checks — full-width Unicode equivalents of `/`, `\`, and `.` (e.g. U+FF0F, U+2215) bypass naive filters applied to raw strings
- Map external identifiers to server-controlled filenames using whitelists or indirect references
- Enforce canonical path validation and containment within safe directories
- Apply defence-in-depth with both input validation and filesystem-level restrictions
- Use platform-safe path handling libraries to prevent traversal attacks

## Remediation Steps

- Trace data flow - Identify where untrusted input (user data, external sources) flows into file operations
- Eliminate direct usage - Replace direct file path construction with indirect references (e.g., map user IDs to predefined filenames)
- Decode and normalise first - URL-decode the raw input (handling single and double encoding) and apply Unicode NFC normalisation before any filtering or path construction
- Implement whitelist validation - Use strict allowlists of permitted filenames or extensions before any file operation
- Canonicalize and validate - Resolve paths to canonical form and verify they remain within intended base directories
- Apply filesystem restrictions - Use chroot jails, restricted permissions, or platform APIs that enforce containment
- Sanitize inputs - If paths must include user data, strip dangerous characters (`.`, `/`, `\`, `%`, `-`) and reject absolute paths; always re-check after decoding
