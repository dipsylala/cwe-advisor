# CWE-434: Unrestricted Upload of File with Dangerous Type

## LLM Guidance

The severity turns on two things the finding will not state: where the file lands - inside the webroot the server may execute or serve it directly - and whether the type check reads the bytes or trusts what the client declared.

## Key Principles

- Validate against an allowlist of business-required file types; do not rely on a blocklist of dangerous extensions
- Verify the file's actual content (signature/magic bytes) rather than the filename extension or client-supplied Content-Type header - but treat that as a filter, not proof. A signature check identifies the prefix only, so a polyglot carrying a valid header followed by script passes every signature test ever written; re-encoding the file through a decode-and-re-save is what removes the payload
- Store uploaded files outside the webroot or in storage incapable of executing scripts; serve them back only through application-controlled logic
- Generate a new filename for storage; never use the original filename or client-supplied path as the storage path
- Derive the stored *extension* from the detected type through a fixed `mime -> ext` allowlist map: the extension is what decides how the file is later served, so a generated name carrying the client's original suffix still lets the attacker choose the half that matters
- Enforce file size limits and re-encode formats that can carry active content (e.g., images) before trusting them
- Require authentication, authorization, and CSRF protection on upload endpoints as defence-in-depth

## Remediation Steps

- Locate - Identify the upload endpoint (source) and where the file is written to storage or later served back (sink)
- Trace data flow - Follow the filename, extension, and content-type from the request through storage and any code path that serves the file back to a client
- Identify the unsafe pattern - Trusting the client-supplied extension or MIME type alone, using the original filename as the storage path, or storing inside the webroot
- Replace with the safe pattern - Allowlist the file type by inspecting content, generate a random storage filename whose extension comes from the detected type's allowlist entry, and store outside the webroot
- Break taint after allowlist validation - Use the allowlist-matched type for storage and handling decisions, not the raw client-supplied value
- Add secondary controls - Size limits, malware scanning, and safe response headers when serving files back. Send `X-Content-Type-Options: nosniff` always, and `Content-Disposition: attachment` for anything a browser renders as a document (HTML, SVG, XML, PDF); a raster image the allowlist already re-encoded can be served inline, and forcing attachment on it turns an avatar the page displayed into a download
- Preserve the caller's contract - storing under a generated name outside the web root breaks any route that built a URL from the original filename, so return the generated name to the caller or persist a mapping in the same change
- Test - Verify rejection of disallowed types, mismatched extension/content pairs, oversized files, and path traversal sequences in filenames - and, on the accept side, that a genuine upload can still be retrieved afterwards through whatever path the response or a follow-up request uses. Only that last assertion catches a rename that broke every legitimate download while leaving every rejection test passing
