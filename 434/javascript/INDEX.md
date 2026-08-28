# CWE-434: Unrestricted Upload of File with Dangerous Type - JavaScript

## LLM Guidance

Node.js applications typically handle uploads with `multer`. The common mistake is filtering in `fileFilter` on `file.mimetype` or the extension of `file.originalname` - both are supplied by the client in the multipart request and are not verified by multer itself. Validate the actual bytes (magic numbers) after the file is written or buffered, cap size with `limits.fileSize`, and store outside any directory served by `express.static`.

## Key Principles

- Do not trust `file.mimetype` or the extension in `file.originalname` inside `fileFilter` - both are attacker-controlled request metadata, not verified content
- Check magic bytes with a library such as `file-type` (`fileTypeFromBuffer`/`fileTypeFromFile`) against an allowlist after the bytes are available; `file-type` is ESM-only from v17, so a CommonJS handler must load it with a dynamic `await import('file-type')`
- Set `limits: { fileSize }` in the multer configuration to reject oversized uploads before they consume memory or disk
- Prefer `multer.diskStorage` with a generated filename over the default memory storage for anything beyond small files, since memory storage buffers the whole file in RAM
- Store uploads outside any path passed to `express.static()`; serve files back through a route that streams from the private storage location
- Generate the stored filename (e.g., with `crypto.randomUUID()`); never write using `file.originalname`

## Taint Sinks

`file.originalname`, `file.mimetype`, `multer` `fileFilter` trust, writes into an `express.static` root

## Remediation Steps

- Locate - Find the `multer()` middleware configuration and the route handler that receives `req.file`/`req.files`
- Trace data flow - Follow `file.mimetype`, `file.originalname`, and the file buffer/path from multer through to storage and any route that serves it back
- Replace the unsafe pattern - Remove any `fileFilter` logic that trusts `mimetype` or the extension alone as the sole gate
- Bind, encode, validate, or authorize - After upload, read the buffer/file and check magic bytes with `file-type`, comparing against an allowlist of permitted types
- Break taint after allowlist validation - Use the detected type and a generated filename for storage and response headers, not the client-supplied values
- Harden configuration - Set `limits.fileSize`, use `diskStorage` with a generated filename function, and store outside `express.static` roots
- Test - Verify rejection of files with forged `mimetype`/extension but disallowed real content, oversized files, and traversal sequences in `originalname`
