# CWE-22: Path Traversal - Java

## LLM Guidance

Path Traversal occurs when user input constructs file paths without validation, allowing attackers to use `../` sequences or absolute paths to access files outside the intended directory. This can expose sensitive files like `/etc/passwd` or `WEB-INF/web.xml`.

**Primary Defence:** Use indirect reference mapping (map IDs to filenames) or validating with `Path.normalize()` and checking the canonical path stays within allowed directories.

## Key Principles

- Use indirect reference maps instead of accepting filenames directly from users
- Decode and Unicode-normalise input before filtering — overlong UTF-8 sequences and full-width Unicode path separators bypass naive string checks; use `java.net.URLDecoder` and `java.text.Normalizer`
- Validate canonical paths remain within the intended base directory
- Reject paths containing traversal sequences (`../`, `..\\`) or null bytes
- Use allowlists for permitted file extensions and directories
- Avoid constructing paths from untrusted input when possible

## Remediation Steps

- Implement indirect object references (user provides ID, application maps to filename)
- Decode URL-encoded input with `URLDecoder.decode(input, StandardCharsets.UTF_8)` and normalise Unicode with `Normalizer.normalize(input, Form.NFC)` before any filtering
- Canonicalize user input with `File.getCanonicalPath()` or `Path.normalize()`
- Verify the resolved path starts with the intended base directory
- Reject requests with traversal sequences, absolute paths, or suspicious characters
- Apply allowlist validation for file extensions if direct input is unavoidable
- Use security manager or sandboxing to restrict file system access

## Safe Pattern

```java
public File getSecureFile(String userInput, String baseDir) throws IOException {
    // Decode and Unicode-normalise before filtering
    String decoded = URLDecoder.decode(userInput, StandardCharsets.UTF_8);
    String normalized = Normalizer.normalize(decoded, Normalizer.Form.NFC);
    
    File base = new File(baseDir).getCanonicalFile();
    File requested = new File(base, normalized).getCanonicalFile();
    
    if (!requested.getPath().startsWith(base.getPath())) {
        throw new SecurityException("Path traversal detected");
    }
    return requested;
}
```
