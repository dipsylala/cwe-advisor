# CWE-73: External Control of File Name or Path - C\#

## LLM Guidance

External control of file names or paths occurs when user-supplied input constructs file system paths without validation in C#/.NET applications. The .NET `System.IO` namespace provides minimal built-in protection against path traversal attacks. Use `Path.GetFullPath()` and `Path.GetRelativePath()` to ensure resolved paths remain within intended base directories.

## Key Principles

- Always validate user-supplied file paths against an allowed base directory
- Canonicalize paths using `Path.GetFullPath()` to resolve traversal sequences (`../`, `..\\`)
- Decode and Unicode-normalise input before filtering: use `Uri.UnescapeDataString()` and `string.Normalize(NormalizationForm.FormC)` - overlong UTF-8 or full-width Unicode separators bypass checks on raw strings
- Use allowlists for file extensions and names when possible
- Never trust `IFormFile.FileName` or any user-controlled path input directly
- Implement defence-in-depth with filesystem permissions

## Remediation Steps

- Identify sources - Find untrusted input from `Request.Query`, `Request.Form`, `IFormFile.FileName`, route parameters, headers, or deserialized objects
- Trace to sinks - Locate file operations using `File.*()` methods, `FileStream`, `StreamReader/Writer`, `FileInfo`, or `Path.Combine()`
- Define base directory - Establish an allowed root directory for file operations
- Decode and normalise - Call `Uri.UnescapeDataString(userInput)` then `.Normalize(NormalizationForm.FormC)` before any character filtering
- Canonicalize paths - Use `Path.GetFullPath()` to resolve the full absolute path
- Validate containment - Use `Path.GetRelativePath()` and reject rooted paths or paths beginning with `..`
- Implement allowlists - Validate file extensions and names against approved patterns

## Safe Pattern

```csharp
string baseDirectory = Path.GetFullPath("/safe/files/");
string userInput = Request.Query["filename"];

// Decode URL encoding and Unicode-normalise before filtering
string decoded = Uri.UnescapeDataString(userInput).Normalize(NormalizationForm.FormC);

// Combine and canonicalize
string requestedPath = Path.Combine(baseDirectory, decoded);
string fullPath = Path.GetFullPath(requestedPath);

// Validate path stays within base directory
string relativePath = Path.GetRelativePath(baseDirectory, fullPath);
if (Path.IsPathRooted(relativePath) || relativePath.StartsWith(".."))
{
    throw new UnauthorizedAccessException("Invalid file path");
}

// Safe to proceed
byte[] content = File.ReadAllBytes(fullPath);
```
