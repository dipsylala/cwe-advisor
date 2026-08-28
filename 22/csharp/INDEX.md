# CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - C#

## LLM Guidance

Path Traversal occurs when user-supplied input constructs file paths without validation, allowing attackers to use `../` sequences or absolute paths to access files outside intended directories. The core fix is to use indirect reference mapping (map IDs to filenames) or validate paths with `Path.GetFullPath()` and ensure they remain within the allowed base directory.

## Key Principles

- Never directly concatenate user input into file paths
- Use allowlists for filenames, not denylists for patterns
- Do not re-decode: ASP.NET model binding and `Request.Query` already return decoded values, so a further `Uri.UnescapeDataString()` manufactures `../` from the inert literal `%2e%2e%2f`; U+FF0F is not a separator to the filesystem, so normalisation is not the control
- Canonicalize paths with `Path.GetFullPath()` before validation
- Always verify resolved paths start with the intended base directory
- Compare with `Path.GetRelativePath()` rather than `fullPath.StartsWith(baseDir)` - a bare string prefix accepts a sibling such as `C:\uploads-secret`; reject when the relative result is `..`, starts with `".." + Path.DirectorySeparatorChar`, or satisfies `Path.IsPathRooted()`
- `Path.GetFullPath()` normalizes `..` but does not resolve symbolic links or junctions; where the base directory may contain attacker-planted links, follow up with `FileInfo.ResolveLinkTarget(returnFinalTarget: true)` and re-check containment on the resolved target
- Prefer indirect references (database IDs mapped to filenames)
- Archive extraction (Zip Slip): treat `ZipArchiveEntry.FullName` as untrusted - combine it with the destination directory, canonicalize with `Path.GetFullPath()`, and verify the result starts with the destination directory (with a trailing separator) before extracting; `ZipFile.ExtractToDirectory()` validates this internally in modern .NET (Core 2.1+), but manual per-entry extraction loops do not

## Taint Sinks

`File.ReadAllText()`, `File.Open()`, `Path.Combine()` with unvalidated input, `ZipArchiveEntry.FullName` (Zip Slip)

## Remediation Steps

- Identify all user inputs that influence file operations (reads, writes, includes)
- Validate the value model binding already decoded - add no second `Uri.UnescapeDataString()` pass before filtering
- Replace direct path construction with safe methods using `Path.Combine()`
- Implement base directory validation after canonicalizing with `Path.GetFullPath()`
- Strip or reject path traversal sequences (`..`, absolute paths) from user input
- Use allowlist validation for permitted filenames or extensions
- Test with payloads - `../`, `..\\`, absolute paths, encoded variants (`%2e%2e%2f`, `%c0%ae`), full-width characters
