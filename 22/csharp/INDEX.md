# CWE-22: Path Traversal - C\#

## LLM Guidance

Path Traversal occurs when user-supplied input constructs file paths without validation, allowing attackers to use `../` sequences or absolute paths to access files outside intended directories. The core fix is to use indirect reference mapping (map IDs to filenames) or validate paths with `Path.GetFullPath()` and ensure they remain within the allowed base directory.

## Key Principles

- Never directly concatenate user input into file paths
- Use allowlists for filenames, not denylists for patterns
- URL-decode and Unicode-normalise input before any filtering — overlong UTF-8 or full-width Unicode characters (e.g. U+FF0F) can bypass raw string checks
- Canonicalize paths with `Path.GetFullPath()` before validation
- Always verify resolved paths start with the intended base directory
- Prefer indirect references (database IDs mapped to filenames)

## Remediation Steps

- Identify all user inputs that influence file operations (reads, writes, includes)
- URL-decode input with `Uri.UnescapeDataString()` and normalise Unicode with `inputString.Normalize(NormalizationForm.FormC)` before any filtering
- Replace direct path construction with safe methods using `Path.Combine()`
- Implement base directory validation after canonicalizing with `Path.GetFullPath()`
- Strip or reject path traversal sequences (`..`, absolute paths) from user input
- Use allowlist validation for permitted filenames or extensions
- Test with payloads - `../`, `..\\`, absolute paths, encoded variants (`%2e%2e%2f`, `%c0%ae`), full-width characters

## Safe Pattern

```csharp
public string GetSafeFilePath(string userInput, string baseDirectory)
{
    // Decode and Unicode-normalise before any filtering
    string decoded = Uri.UnescapeDataString(userInput).Normalize(NormalizationForm.FormC);
    
    // Strip to filename only (removes any directory components)
    string fileName = Path.GetFileName(decoded);
    
    // Combine with base directory and canonicalize
    string fullPath = Path.GetFullPath(Path.Combine(baseDirectory, fileName));
    
    // Verify path stays within base directory
    if (!fullPath.StartsWith(Path.GetFullPath(baseDirectory), StringComparison.OrdinalIgnoreCase))
        throw new UnauthorizedAccessException("Invalid path");
    
    return fullPath;
}
```
