# CWE-73: External Control of File Name or Path

## LLM Guidance

This vulnerability occurs when user input is used to construct file or directory names, allowing attackers to read, write, or delete arbitrary files on the system. Attackers can exploit path traversal (e.g., `../../../etc/passwd`) or absolute paths to access sensitive files outside intended directories, but the weakness does not require traversal at all - choosing which file inside an allowed directory gets read, written, or deleted is the same finding. Where the payload does escape the directory, apply CWE-22 as well; where validation is defeated by two spellings of the same path, apply CWE-41.

## Key Principles

- Never use untrusted data directly as file names or path components
- Decode fully before filtering: URL-decode input (including double-encoded variants such as `%252e`) and do not reach for Unicode NFC normalisation as the answer to full-width look-alikes - NFC leaves U+FF0F, U+FF3C, U+FF0E and U+2215 all unchanged, and even NFKC folds only the first three, so normalisation is not the control here. These characters are not path separators to the filesystem; the containment check on the resolved path is what refuses them
- Map external identifiers to server-controlled filenames using whitelists or indirect references
- Enforce canonical path validation and containment within safe directories
- Containment is not authorization: confirming a path resolves inside the base directory says nothing about whether this caller may access that file, and a successful `File.Exists()`/`os.path.isfile()` check is not an access decision
- Check the value you will actually use - deriving a cleaned copy for the check and then passing the original input to the file operation validates a string that is never opened
- An extension allowlist constrains the file type, not the directory: `../../secrets/config.pdf` ends in `.pdf` too
- Apply defence-in-depth with both input validation and filesystem-level restrictions
- Use platform-safe path handling libraries to prevent traversal attacks

## Remediation Steps

- Trace data flow - Identify where untrusted input (user data, external sources) flows into file operations
- Eliminate direct usage - Replace direct file path construction with indirect references (e.g., map user IDs to predefined filenames)
- Decode and normalise first - URL-decode the raw input (handling single and double encoding) and apply Unicode NFC normalisation before any filtering or path construction
- Implement whitelist validation - Use strict allowlists of permitted filenames or extensions before any file operation
- Canonicalize and validate - Resolve paths to canonical form and verify they remain within intended base directories
- Apply filesystem restrictions - Use chroot jails, restricted permissions, or platform APIs that enforce containment
- Reject rather than sanitize - refuse input containing path separators, traversal sequences, null bytes, or an absolute path rather than stripping them; a single-pass strip is bypassable (`....//` collapses to `../`) and hides the attempt from logs
- Authorize separately - after containment passes, check that this user owns or may access the selected file, before the operation runs
