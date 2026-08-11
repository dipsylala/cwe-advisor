# CWE-434: Unrestricted Upload of File with Dangerous Type - Python

## LLM Guidance

In Flask and Django, uploads arrive through `request.files` or a `FileField`. A common misconception is that `werkzeug.utils.secure_filename()` performs type validation - it only sanitizes the filename string (strips path separators and unsafe characters) and says nothing about the file's actual content. Validate real content with `python-magic` or, for images, Pillow's own format verification, independent of filename sanitization.

## Key Principles

- `secure_filename()` is filename sanitization only - it prevents path traversal and unsafe characters in the name, but performs no content or type validation; always pair it with a separate content check
- Never trust the client-supplied `file.content_type` (Flask) or `uploaded_file.content_type` (Django) - both come from the multipart request headers
- Detect the real file type from bytes using `python-magic` (`magic.from_buffer(data, mime=True)`) and check it against an allowlist
- For images specifically, `PIL.Image.open()` followed by `img.verify()` (or re-saving via `img.load()`/re-encode) confirms the bytes are a valid, parseable image of the claimed format
- In Django, `FileField(upload_to=...)` controls the storage subpath but does not validate content; add a `validators=[...]` callable or clean method that performs the magic-byte check before save
- Store uploads outside `STATIC_ROOT`/`MEDIA_ROOT` if they should not be directly web-accessible, or serve them through a view that enforces access control rather than direct static serving

## Taint Sinks

`secure_filename()`, `file.content_type`, `uploaded_file.content_type`, `FileField`

## Remediation Steps

- Locate - Find where `request.files['x']` (Flask) or a `FileField`/`ImageField` (Django) receives the upload
- Trace data flow - Follow the filename, `content_type`, and file bytes from the request through `secure_filename()`, storage, and any view that serves the file back
- Replace the unsafe pattern - Stop treating `secure_filename()` or `content_type` as sufficient validation of file type
- Bind, encode, validate, or authorize - Read the file bytes, detect the type with `python-magic` (or verify with Pillow for images), and compare against an allowlist
- Break taint after allowlist validation - Use the detected type and a generated filename (e.g., `uuid.uuid4()`) for storage, keeping `secure_filename()` only as a defence-in-depth sanitizer on the display name
- Harden configuration - Set `MAX_CONTENT_LENGTH` (Flask) or `FILE_UPLOAD_MAX_MEMORY_SIZE`/`DATA_UPLOAD_MAX_MEMORY_SIZE` (Django) to bound upload size
- Test - Verify rejection of files with a disallowed real type despite an allowed extension/content-type, oversized files, and traversal sequences in the original filename

## Safe Pattern

```python
# SAFE: magic-byte validation, generated filename, storage outside webroot
import os
import uuid
import magic  # python-magic

UPLOAD_DIR = "/var/app-data/uploads"  # outside STATIC_ROOT/MEDIA_ROOT
ALLOWED_TYPES = {"image/png": "png", "image/jpeg": "jpg"}
MAX_BYTES = 5 * 1024 * 1024

def store_upload(file_storage) -> str:
    data = file_storage.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("File too large")

    # SAFE: detect real type from bytes, not the client-supplied content_type
    detected_type = magic.from_buffer(data, mime=True)
    if detected_type not in ALLOWED_TYPES:
        raise ValueError(f"Unsupported file type: {detected_type}")

    stored_name = f"{uuid.uuid4()}.{ALLOWED_TYPES[detected_type]}"
    target_path = os.path.join(UPLOAD_DIR, stored_name)

    with open(target_path, "wb") as f:
        f.write(data)

    return stored_name
```
