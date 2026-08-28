# CWE-41: Improper Resolution of Path Equivalence - C#

## LLM Guidance

In .NET this appears when `Path.Combine()` builds a path from user input and the access-control check then runs on that un-normalized string. `Path.Combine()` concatenates and normalizes separators but does not resolve `.` or `..`, so `C:\App\Documents\..\..\Windows\System32\config\SAM` genuinely starts with `C:\App\Documents\` and passes a `StartsWith()` test - while the file API resolves the traversal on the way out. The fix is to canonicalize with `Path.GetFullPath()` first, then check containment with `Path.GetRelativePath()` rather than a string prefix.

## Key Principles

- Canonicalize with `Path.GetFullPath()` before any comparison; a check against a `Path.Combine()` result is a check against a string the filesystem will never see
- Verify containment with `Path.GetRelativePath(baseDir, canonicalPath)` and reject a result that is `..`, starts with `..` plus a separator, or is rooted - this avoids both the traversal bypass and the sibling-directory bypass (`C:\App\Documents-secret`)
- Where only a filename is expected, require `Path.GetFileName(name) == name` and reject input containing a path separator or any of `Path.GetInvalidFileNameChars()`, which also blocks alternate data stream tricks
- If a string comparison is unavoidable, pass `StringComparison.Ordinal` - `StartsWith(string)` defaults to a culture-sensitive comparison that can treat different strings as equal
- `Path.GetFullPath()` does not follow symbolic links or junctions; where reparse-point escapes are in scope, check `File.GetAttributes()` for `FileAttributes.ReparsePoint` (or resolve with `FileInfo.ResolveLinkTarget(returnFinalTarget: true)`) and re-verify containment
- Confirm the target is a regular file rather than a directory before serving it, and pass the canonical path - not the original input - to the file API

## Taint Sinks

`Path.Combine()` with unvalidated input, `File.ReadAllBytes()`, `File.Open()`, `PhysicalFile()`, `Directory.GetFiles()`

## Remediation Steps

- Locate - find path comparisons or containment checks (`StartsWith`, `==`, `Contains`) applied to a path built from route values, query strings, or form data
- Trace data flow - follow the value from the action parameter through `Path.Combine()` to the comparison and then to the file API, noting whether the compared value and the opened value are the same variable
- Replace the unsafe pattern - resolve the base directory once with `Path.GetFullPath()` into a `static readonly` field, canonicalize the requested path, and compare with `Path.GetRelativePath()`
- Bind, encode, validate, or authorize - reject names containing separators or invalid filename characters before combining, and apply an extension allowlist where only certain types are legitimate
- Break taint after allowlist validation - pass the canonical path variable to `PhysicalFile()`/`File.Open()`, never the request value
- Harden configuration - check `FileAttributes.ReparsePoint` where symlinks or junctions may exist in the served tree, and restrict the process account's filesystem permissions to that tree
- Test - assert equivalent spellings of the same path (`dir`, `dir\`, `dir\.`, `dir\\`) reach the same decision, that `..\..\` payloads are refused, and that a legitimate file still downloads
