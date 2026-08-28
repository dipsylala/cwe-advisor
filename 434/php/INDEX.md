# CWE-434: Unrestricted Upload of File with Dangerous Type - PHP

## LLM Guidance

PHP uploads arrive via the `$_FILES` superglobal and are typically persisted with `move_uploaded_file()`. The common mistake is trusting `$_FILES['x']['type']`, which is the client-supplied `Content-Type` header from the multipart request and not verified by PHP. Validate the real content with `finfo_file()` (magic-byte detection), never place uploads in a script-executable directory, and generate the stored filename server-side.

## Key Principles

- Never trust `$_FILES['x']['type']` or the extension of `$_FILES['x']['name']` - both come from the client and can be set to anything
- Detect the real MIME type from the uploaded file's bytes using the Fileinfo extension (`finfo_open(FILEINFO_MIME_TYPE)` + `finfo_file()`), and check it against an allowlist
- Disable script execution in the upload directory: an `.htaccess` with `php_flag engine off` (Apache) or, for nginx, a `location` block that does not pass `.php` requests in that path to PHP-FPM - do this even when files are also stored outside the webroot, as defence-in-depth
- Store uploads outside the document root (`DOCUMENT_ROOT`) whenever possible; serve them back through a script that streams the file, not by direct URL
- Generate the stored filename server-side, for example with `bin2hex(random_bytes(16))`; never build the storage path from `$_FILES['x']['name']`
- Enforce `upload_max_filesize`/`post_max_size` in `php.ini` and re-check size in code, since `$_FILES['x']['size']` alone is not sufficient validation
- `$_FILES['file']['type']` is the client's claim and `$_FILES['file']['name']` is the client's filename - use neither to decide anything; detect the type from the bytes with `finfo`
- A double extension (`invoice.pdf.php`) is executed by a server configured to run the last one, so validate the *final* extension against an allowlist and store under a server-generated name outside the document root

## Taint Sinks

`move_uploaded_file()`, `$_FILES['x']['name']`, `$_FILES['x']['type']`

## Remediation Steps

- Locate - Find where `$_FILES` is read and where `move_uploaded_file()` (or equivalent) writes the file
- Trace data flow - Follow `$_FILES['x']['type']`, `['name']`, and `['tmp_name']` from the request to storage and any code that serves the file back
- Replace the unsafe pattern - Remove any check that trusts `$_FILES['x']['type']` or the extension of `$_FILES['x']['name']` as the sole gate
- Bind, encode, validate, or authorize - Run `finfo_file()` on `$_FILES['x']['tmp_name']`, compare the detected MIME type against an allowlist, and reject on mismatch
- Break taint after allowlist validation - Use the finfo-detected type and a server-generated filename for storage, not the client-supplied name or type
- Harden configuration - Store outside the document root, disable script execution in the upload directory, and set `upload_max_filesize`/`post_max_size`
- Test - Verify rejection of files with forged `type`/extension but disallowed real content, oversized files, and traversal sequences (`../`) in the original name
