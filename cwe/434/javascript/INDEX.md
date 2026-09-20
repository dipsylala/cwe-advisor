# CWE-434: Unrestricted Upload of File with Dangerous Type - JavaScript

## LLM Guidance

Node.js applications typically handle uploads with `multer`. The common mistake is filtering in `fileFilter` on `file.mimetype` or the extension of `file.originalname` - both are supplied by the client in the multipart request and are not verified by multer itself. Validate the actual bytes (magic numbers) after the file is written or buffered, cap size with `limits.fileSize`, and store outside any directory served by `express.static`.

## Key Principles

- Do not trust `file.mimetype` or the extension in `file.originalname` inside `fileFilter` - both are attacker-controlled request metadata, not verified content
- Check magic bytes with a library such as `file-type` (`fileTypeFromBuffer`/`fileTypeFromFile`) against an allowlist after the bytes are available - which is never inside `fileFilter`. multer calls `fileFilter` before it hands the file to the storage engine, so at that point `file.buffer` (memory storage) and the written path (disk storage) do not exist yet; a `fileTypeFromBuffer(file.buffer)` placed in `fileFilter` is called with `undefined` and throws `TypeError`, which inside an async `fileFilter` is an unhandled rejection that leaves multer's `cb` uncalled - the request hangs, or the process exits. Detect in the route handler after `upload.single()`/`upload.array()` has run, from `req.file.buffer` or `req.file.path`, and with `diskStorage` unlink the file when the check fails. That ordering also means the detected extension cannot be applied when the file is named: `diskStorage`'s `filename` callback runs before any bytes are written, so name it `<uuid>.tmp` there and `fs.rename` to `<uuid>.<detected.ext>` once the check passes. `file-type` is ESM-only from v17, but `require()` of an ESM module without top-level await is supported from Node 20.19/22.12/23, so `require('file-type')` works on every supported runtime (verified on Node 24 with file-type 22.1.1); reach for `await import('file-type')` only on an older one
- Set `limits: { fileSize }` in the multer configuration to reject oversized uploads before they consume memory or disk - on multer below 2.3.0 an asynchronous `fileFilter` defeats that limit entirely (CVE-2026-77063), so 2.3.0 is the floor for this control to mean anything. Take `file-type` at 21.3.2 or later, which is where its zip-bomb denial of service was fixed - it is reachable from `fileTypeFromBuffer` on exactly the attacker bytes this entry tells you to hand it
- Prefer `multer.diskStorage` with a generated filename over the default memory storage for anything beyond small files, since memory storage buffers the whole file in RAM
- Store uploads outside any path passed to `express.static()`; serve files back through a route that streams from the private storage location with `res.sendFile()` - `res.download()` adds `Content-Disposition: attachment`, which turns an avatar the page rendered inline into a file download
- Generate the stored filename with `crypto.randomUUID()` and take the extension from the detection result - `fileTypeFromBuffer` returns both `mime` and `ext`, so use `detected.ext` - never from `file.originalname`. The extension is what decides how the file is served back, so it must come from the detected type rather than the client

## Taint Sinks

`file.originalname`, `file.mimetype`, `multer` `fileFilter` trust, writes into an `express.static` root

## Remediation Steps

- Locate - Find the `multer()` middleware configuration and the route handler that receives `req.file`/`req.files`
- Trace data flow - Follow `file.mimetype`, `file.originalname`, and the file buffer/path from multer through to storage and any route that serves it back
- Replace the unsafe pattern - Remove any `fileFilter` logic that trusts `mimetype` or the extension alone as the sole gate
- Bind, encode, validate, or authorize - In the route handler, after the multer middleware has run and never inside `fileFilter`, read `req.file.buffer` or `req.file.path` and check magic bytes with `file-type`, comparing against an allowlist of permitted types; remove a disk-stored file that fails
- Break taint after allowlist validation - Use the detected type and a generated filename for storage and response headers, not the client-supplied values
- Harden configuration - Set `limits.fileSize`, use `diskStorage` with a generated filename function, and store outside `express.static` roots
- Test - Verify rejection of files with forged `mimetype`/extension but disallowed real content, oversized files, and traversal sequences in `originalname`
