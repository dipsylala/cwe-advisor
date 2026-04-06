# CWE-73: External Control of File Name or Path - Java

## LLM Guidance

External control of file names or paths occurs when untrusted input (HTTP requests, uploads, APIs) constructs file system paths without validation in Java applications. Java's `File`, `Path`, and I/O classes lack built-in path traversal protection, making applications vulnerable when user input directly influences file operations.

## Key Principles

- Validate all file names/paths against an allowlist of permitted values or patterns
- Decode and Unicode-normalise input before filtering: use `URLDecoder.decode()` and `Normalizer.normalize(input, Form.NFC)` — overlong UTF-8 sequences and Unicode full-width separators bypass checks on raw strings
- Use canonical paths to resolve symbolic links and relative references (`.`, `..`)
- Restrict file operations to a defined base directory using path normalization
- Never concatenate user input directly into file paths
- Sanitize file names by removing directory traversal sequences

## Remediation Steps

- Identify untrusted sources - Locate where external data enters (`request.getParameter()`, `@PathVariable`, `MultipartFile.getOriginalFilename()`, headers, JSON/XML fields)
- Trace to file operations - Find sinks using `new File()`, `Files.readAllBytes()`, `Paths.get()`, `FileReader/Writer`, or I/O constructors
- Validate against allowlist - Check file names/extensions against permitted values before use
- Decode and normalise - Call `URLDecoder.decode(input, StandardCharsets.UTF_8)` and `Normalizer.normalize(decoded, Form.NFC)` before any character filtering
- Canonicalize paths - Use `File.getCanonicalPath()` or `Path.toRealPath()` to resolve traversals
- Enforce base directory - Verify canonical path starts with approved base directory
- Reject invalid input - Return error for paths failing validation; never allow fallback to user input

## Safe Pattern

```java
public Path getSafeFilePath(String userFilename, Path baseDir) throws IOException {
    // Decode URL encoding and Unicode-normalise before filtering
    String decoded = URLDecoder.decode(userFilename, StandardCharsets.UTF_8);
    String normalised = Normalizer.normalize(decoded, Normalizer.Form.NFC);
    
    // Remove traversal sequences after decoding
    String sanitized = normalised.replaceAll("[./\\\\]", "");
    
    // Build path within base directory
    Path requestedPath = baseDir.resolve(sanitized).normalize();
    Path canonicalPath = requestedPath.toRealPath();
    
    // Verify within base directory
    if (!canonicalPath.startsWith(baseDir.toRealPath())) {
        throw new SecurityException("Invalid path");
    }
    return canonicalPath;
}
```
