# CWE-434: Unrestricted Upload of File with Dangerous Type

## LLM Guidance

This weakness occurs when an application accepts uploaded files without validating their type, content, or storage location, allowing an attacker to upload an executable script, a web shell, or a file with active content (such as HTML or SVG carrying script). It is especially severe when uploads land inside the webroot where the server will execute or directly serve them. The core fix is to allowlist permitted file types by inspecting actual content, store files outside the webroot under a generated name, and never execute uploaded content.

## Key Principles

- Validate against an allowlist of business-required file types; do not rely on a blocklist of dangerous extensions
- Verify the file's actual content (signature/magic bytes), not just the filename extension or client-supplied Content-Type header
- Store uploaded files outside the webroot or in storage incapable of executing scripts; serve them back only through application-controlled logic
- Generate a new filename for storage; never use the original filename or client-supplied path as the storage path
- Enforce file size limits and re-encode formats that can carry active content (e.g., images) before trusting them
- Require authentication, authorization, and CSRF protection on upload endpoints as defence-in-depth

## Remediation Steps

- Locate - Identify the upload endpoint (source) and where the file is written to storage or later served back (sink)
- Trace data flow - Follow the filename, extension, and content-type from the request through storage and any code path that serves the file back to a client
- Identify the unsafe pattern - Trusting the client-supplied extension or MIME type alone, using the original filename as the storage path, or storing inside the webroot
- Replace with the safe pattern - Allowlist the file type by inspecting content, generate a random storage filename, and store outside the webroot
- Break taint after allowlist validation - Use the allowlist-matched type for storage and handling decisions, not the raw client-supplied value
- Add secondary controls - Size limits, malware scanning, and safe response headers (forced attachment download, no-sniff) when serving files back to users
- Test - Verify rejection of disallowed types, mismatched extension/content pairs, oversized files, and path traversal sequences in filenames
