# CWE-434: Unrestricted Upload of File with Dangerous Type - Java

## LLM Guidance

In Spring applications, uploads arrive as `MultipartFile` on a `@PostMapping` handler. The common mistake is trusting `MultipartFile.getContentType()` or `getOriginalFilename()`, both of which are client-supplied HTTP request headers and trivially forged. Validate the actual file bytes with a content-sniffing check, enforce size limits through `spring.servlet.multipart.max-file-size`, and write the file to a generated name outside the web application's static resource directories.

## Key Principles

- Never branch validation logic on `getContentType()` or the extension from `getOriginalFilename()` - both come from the client and are not verified by the server
- Detect the real file type from its bytes with Apache Tika (`org.apache.tika:tika-core`) via `tika.detect(bytes)`, then check the result against an allowlist; `Files.probeContentType()` is not a content check - it takes a `Path` and its default detectors read the file name, so against a server-generated name it validates nothing
- Set `spring.servlet.multipart.max-file-size` and `spring.servlet.multipart.max-request-size` in `application.properties` to bound upload size before the file is fully buffered
- Store files outside `src/main/resources/static`, `webapp`, or any directory Spring serves directly; use a path outside the deployed artifact, such as a configured storage directory or object storage
- Generate the stored filename with `UUID.randomUUID()` rather than reusing `getOriginalFilename()`, which may contain path traversal sequences
- For image uploads, re-encode with `javax.imageio.ImageIO` (read then write) before persisting, which strips embedded scripts or malformed metadata that raw bytes may carry
- Detection identifies the prefix, not the whole file: a valid PNG with a payload appended after `IEND` still detects as `image/png`, so re-encoding - decode and re-emit, discarding everything that was not pixel data - is what removes the payload; a structural parse check is not equivalent

## Taint Sinks

`MultipartFile.getOriginalFilename()`, `MultipartFile.getContentType()`, `transferTo()` into a webroot path

## Remediation Steps

- Locate - Find the `@PostMapping` or `@RequestParam MultipartFile` handler that accepts the upload
- Trace data flow - Follow the file from the controller to wherever it is written with `transferTo()` or an `OutputStream`
- Replace the unsafe pattern - Stop trusting `getContentType()`/`getOriginalFilename()` for validation or as the storage path
- Bind, encode, validate, or authorize - Sniff content type with Tika, compare against an allowlist, generate a random filename, and re-encode images
- Break taint after allowlist validation - Use the Tika-detected (`tika.detect(bytes)`), allowlist-matched type and the generated filename for all subsequent storage logic, not the original request values, and write with `StandardOpenOption.CREATE_NEW`
- Harden configuration - Set `spring.servlet.multipart.max-file-size`/`max-request-size`, and confirm the storage directory is outside any Spring static resource path
- Test - Verify rejection of files with mismatched extension/content (e.g., a `.jpg` that is actually an executable), oversized files, and traversal sequences in the original filename
