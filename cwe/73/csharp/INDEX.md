# CWE-73: External Control of File Name or Path - C#

## LLM Guidance

External control of file names or paths occurs when user-supplied input constructs file system paths without validation in C#/.NET applications. The .NET `System.IO` namespace provides minimal built-in protection against path traversal attacks. Use `Path.GetFullPath()` and `Path.GetRelativePath()` to ensure resolved paths remain within intended base directories.

## Key Principles

- Always validate user-supplied file paths against an allowed base directory
- Canonicalize paths using `Path.GetFullPath()` to resolve traversal sequences (`../`, `..\\`) - `GetFullPath()` alone does not confine anything: `Path.GetFullPath(@"C:\Windows\win.ini")` returns that exact path, since a rooted/absolute input needs no traversal sequence at all. Pair it with a containment check against the base directory, never treat canonicalization as sufficient on its own
- Open an upload with `FileMode.CreateNew`, not `FileMode.Create` - `Create` silently truncates an existing file, so a user-influenced name that collides with `web.config` or another real file overwrites it even after path validation passes
- Decode and Unicode-normalise input before filtering: use `Uri.UnescapeDataString()` and `string.Normalize(NormalizationForm.FormC)` - overlong UTF-8 or full-width Unicode separators bypass checks on raw strings
- Use allowlists for file extensions and names when possible
- Never trust `IFormFile.FileName` or any user-controlled path input directly - store an upload under a server-generated name (`Path.GetRandomFileName()`) and keep the submitted name only as metadata
- Include the separator in the containment check (`".." + Path.DirectorySeparatorChar`) and pass `StringComparison.Ordinal`; a bare `StartsWith("..")` is culture-sensitive and also rejects a legitimate name beginning with two dots
- `File.Exists()` is not an authorization check - confirm the caller may access the selected file before opening it
- Implement defence-in-depth with filesystem permissions

## Taint Sinks

`File.*()` methods, `FileStream`, `StreamReader`/`StreamWriter`, `Path.Combine()` with unvalidated input

## Remediation Steps

- Identify sources - Find untrusted input from `Request.Query`, `Request.Form`, `IFormFile.FileName`, route parameters, headers, or deserialized objects
- Trace to sinks - Locate file operations using `File.*()` methods, `FileStream`, `StreamReader/Writer`, `FileInfo`, or `Path.Combine()`
- Define base directory - Establish an allowed root directory for file operations
- Decode and normalise - Call `Uri.UnescapeDataString(userInput)` then `.Normalize(NormalizationForm.FormC)` before any character filtering
- Canonicalize paths - Use `Path.GetFullPath()` to resolve the full absolute path
- Validate containment - Use `Path.GetRelativePath()` and reject rooted paths or paths beginning with `..`
- Implement allowlists - Validate file extensions and names against approved patterns
