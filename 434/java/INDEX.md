# CWE-434: Unrestricted Upload of File with Dangerous Type - Java

## LLM Guidance

In Spring applications, uploads arrive as `MultipartFile` on a `@PostMapping` handler. The common mistake is trusting `MultipartFile.getContentType()` or `getOriginalFilename()`, both of which are client-supplied HTTP request headers and trivially forged. Validate the actual file bytes with a content-sniffing check, enforce size limits through `spring.servlet.multipart.max-file-size`, and write the file to a generated name outside the web application's static resource directories.

## Key Principles

- Never branch validation logic on `getContentType()` or the extension from `getOriginalFilename()` - both come from the client and are not verified by the server
- Detect the real file type from its bytes using Apache Tika (`org.apache.tika:tika-core`) or `java.nio.file.Files.probeContentType()` on the saved bytes, then check the detected type against an allowlist
- Set `spring.servlet.multipart.max-file-size` and `spring.servlet.multipart.max-request-size` in `application.properties` to bound upload size before the file is fully buffered
- Store files outside `src/main/resources/static`, `webapp`, or any directory Spring serves directly; use a path outside the deployed artifact, such as a configured storage directory or object storage
- Generate the stored filename with `UUID.randomUUID()` rather than reusing `getOriginalFilename()`, which may contain path traversal sequences
- For image uploads, re-encode with `javax.imageio.ImageIO` (read then write) before persisting, which strips embedded scripts or malformed metadata that raw bytes may carry

## Remediation Steps

- Locate - Find the `@PostMapping` or `@RequestParam MultipartFile` handler that accepts the upload
- Trace data flow - Follow the file from the controller to wherever it is written with `transferTo()` or an `OutputStream`
- Replace the unsafe pattern - Stop trusting `getContentType()`/`getOriginalFilename()` for validation or as the storage path
- Bind, encode, validate, or authorize - Sniff content type with Tika, compare against an allowlist, generate a random filename, and re-encode images
- Break taint after allowlist validation - Use the Tika-detected, allowlist-matched type and the generated filename for all subsequent storage logic, not the original request values
- Harden configuration - Set `spring.servlet.multipart.max-file-size`/`max-request-size`, and confirm the storage directory is outside any Spring static resource path
- Test - Verify rejection of files with mismatched extension/content (e.g., a `.jpg` that is actually an executable), oversized files, and traversal sequences in the original filename

## Safe Pattern

```java
// SAFE: content-sniffed validation, generated filename, storage outside webroot
import org.apache.tika.Tika;
import org.springframework.web.multipart.MultipartFile;
import java.nio.file.*;
import java.util.Set;
import java.util.UUID;

private static final Set<String> ALLOWED_TYPES = Set.of("image/png", "image/jpeg");
private static final Path UPLOAD_DIR = Paths.get("/var/app-data/uploads"); // outside webroot
private final Tika tika = new Tika();

public String storeUpload(MultipartFile file) throws Exception {
    byte[] content = file.getBytes();

    // SAFE: detect real type from bytes, not the client-supplied header
    String detectedType = tika.detect(content);
    if (!ALLOWED_TYPES.contains(detectedType)) {
        throw new IllegalArgumentException("Unsupported file type: " + detectedType);
    }

    String extension = detectedType.equals("image/png") ? ".png" : ".jpg";
    String storedName = UUID.randomUUID() + extension;
    Path target = UPLOAD_DIR.resolve(storedName).normalize();
    if (!target.startsWith(UPLOAD_DIR)) {
        throw new IllegalArgumentException("Invalid target path");
    }

    Files.write(target, content, StandardOpenOption.CREATE_NEW);
    return storedName;
}
```
