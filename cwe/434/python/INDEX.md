# CWE-434: Unrestricted Upload of File with Dangerous Type - Python

## LLM Guidance

Uploads arrive through `request.files` in Flask, a `FileField` in Django, or an `UploadFile` parameter in FastAPI. A common misconception is that `werkzeug.utils.secure_filename()` performs type validation - it only sanitizes the filename string (strips path separators and unsafe characters) and says nothing about the file's actual content. Validate real content with `python-magic` or, for images, Pillow's own format verification, independent of filename sanitization.

## Key Principles

- `secure_filename()` is filename sanitization only - it prevents path traversal and unsafe characters in the name, but performs no content or type validation; always pair it with a separate content check
- Never trust the client-supplied `file.content_type` (Flask) or `uploaded_file.content_type` (Django) - both come from the multipart request headers
- Detect the real file type from bytes using `python-magic` (`magic.from_buffer(data, mime=True)`) and check it against an allowlist. It is a ctypes wrapper around a system libmagic, so `import magic` fails outright where that is absent - notably on Windows, whose usual shim `python-magic-bin` has not been released since 2017. Where the deployment or CI cannot supply libmagic, `puremagic` is the pure-Python alternative
- For images, `PIL.Image.open()` followed by `img.verify()` confirms the bytes parse as the claimed format, but `verify()` leaves the file object unusable - reopen the file before any `load()` or `save()`, or the follow-on call raises. Re-encoding through a fresh `Image.open()` and `save()` is what strips embedded active content
- In Django, `FileField(upload_to=...)` controls the storage subpath but does not validate content; add a `validators=[...]` callable or clean method that performs the magic-byte check before save
- Store uploads outside `STATIC_ROOT`/`MEDIA_ROOT` if they should not be directly web-accessible, or serve them through a view that enforces access control rather than direct static serving
- Django field `validators=[...]` do run under `full_clean()`, and `ModelForm.is_valid()` calls it - so a magic-byte validator on the field is a real enforcement point for form-driven uploads. The trap is the path that skips it: `Model.objects.create()` and `instance.save()` never call `full_clean()`, so an upload persisted directly from a view bypasses every field validator written for it. A DRF `ModelSerializer` is not that case - it copies `model_field.validators` onto the generated field, so the validator does run in `is_valid()`; the DRF gap is a hand-declared plain `Serializer` field, which inherits nothing
- Derive the stored extension from the detected MIME type through a fixed map; a `uuid4()` filename carrying the client's original suffix still lets the client decide what the server will serve it as
- Store under a server-generated name outside the web root and serve through a handler, so an upload named `shell.php` is never a path the server would execute

## Taint Sinks

`secure_filename()`, `file.content_type`, `uploaded_file.content_type`, `FileField`

## Remediation Steps

- Locate - Find where `request.files['x']` (Flask) or a `FileField`/`ImageField` (Django) receives the upload
- Trace data flow - Follow the filename, `content_type`, and file bytes from the request through `secure_filename()`, storage, and any view that serves the file back
- Replace the unsafe pattern - Stop treating `secure_filename()` or `content_type` as sufficient validation of file type
- Bind, encode, validate, or authorize - Read the file bytes, detect the type with `python-magic` (or verify with Pillow for images), and compare against an allowlist
- Break taint after allowlist validation - Use the detected type and a generated filename (e.g., `uuid.uuid4()`) for storage, keeping `secure_filename()` only as a defence-in-depth sanitizer on the display name
- Harden configuration - Set `MAX_CONTENT_LENGTH` in Flask, which does bound the request. Django has no built-in upload-size ceiling: `FILE_UPLOAD_MAX_MEMORY_SIZE` is only the spool-to-disk threshold and `DATA_UPLOAD_MAX_MEMORY_SIZE` is calculated excluding `request.FILES`, so setting either changes nothing about how large a file may be (on 6.1.1 a 50KB upload is accepted with both set to 1000). Check `uploaded_file.size` in the validator before processing, and cap the body at the reverse proxy
- Serve stored files back through a handler that sets `Content-Type` from the detected type and `X-Content-Type-Options: nosniff`, adding `Content-Disposition: attachment` for the types the root entry lists as browser-rendered documents, rather than exposing the storage directory
- Test - Verify rejection of files with a disallowed real type despite an allowed extension/content-type, oversized files, and traversal sequences in the original filename
