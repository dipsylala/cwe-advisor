# CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - C#

## LLM Guidance

Path Traversal occurs when user-supplied input constructs file paths without validation, allowing attackers to use `../` sequences or absolute paths to access files outside intended directories. The core fix is to use indirect reference mapping (map IDs to filenames) or validate paths with `Path.GetFullPath()` and ensure they remain within the allowed base directory.

## Key Principles

- Never directly concatenate user input into file paths
- Use allowlists for filenames, not denylists for patterns
- URL-decode and Unicode-normalise input before any filtering - overlong UTF-8 or full-width Unicode characters (e.g. U+FF0F) can bypass raw string checks
- Canonicalize paths with `Path.GetFullPath()` before validation
- Always verify resolved paths start with the intended base directory
- Prefer indirect references (database IDs mapped to filenames)
- Archive extraction (Zip Slip): treat `ZipArchiveEntry.FullName` as untrusted - combine it with the destination directory, canonicalize with `Path.GetFullPath()`, and verify the result starts with the destination directory (with a trailing separator) before extracting; `ZipFile.ExtractToDirectory()` validates this internally in modern .NET (Core 2.1+), but manual per-entry extraction loops do not

## Taint Sinks

`File.ReadAllText()`, `File.Open()`, `Path.Combine()` with unvalidated input, `ZipArchiveEntry.FullName` (Zip Slip)

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
    string fullBase = Path.GetFullPath(baseDirectory);
    string fullPath = Path.GetFullPath(Path.Combine(fullBase, fileName));
    
    // Verify path stays within base directory using a relative-path check,
    // not a raw string prefix - a prefix check without a trailing separator
    // would incorrectly accept a sibling directory (e.g. "baseDir-evil")
    string relative = Path.GetRelativePath(fullBase, fullPath);
    bool escapesBase = relative == ".." || relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal);
    if (escapesBase || Path.IsPathRooted(relative))
        throw new UnauthorizedAccessException("Invalid path");
    
    return fullPath;
}
```
