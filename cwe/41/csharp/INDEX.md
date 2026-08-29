# CWE-41: Improper Resolution of Path Equivalence - C#

## LLM Guidance

In .NET this appears when `Path.Combine()` builds a path from user input and the access-control check then runs on that un-normalized string. `Path.Combine()` does not resolve `.` or `..`, so `C:\App\Documents\..\..\Windows\System32\config\SAM` genuinely starts with `C:\App\Documents\` and passes a `StartsWith()` test - while the file API resolves the traversal on the way out. The fix is to canonicalize with `Path.GetFullPath()` first, then check containment with `Path.GetRelativePath()` rather than a string prefix.

## Key Principles

- Canonicalize with `Path.GetFullPath()` before any comparison; a check against a `Path.Combine()` result is a check against a string the filesystem will never see
- **`Path.Combine()` discards everything before a rooted argument** - the docs say so and direct you to `Path.Join()` for that reason: "if an argument other than the first contains a rooted path, any previous path components are ignored". So `Combine(baseDir, "C:\\Windows\\win.ini")` returns the attacker's path and the base is gone before any check runs. Use `Path.Join()` where the later segments are user input, since it concatenates without that reset
- Verify containment with `Path.GetRelativePath(baseDir, canonicalPath)` and reject a result that is `..`, starts with `..` plus either `Path.DirectorySeparatorChar` or `Path.AltDirectorySeparatorChar`, or is rooted - this avoids both the traversal bypass and the sibling-directory bypass (`C:\App\Documents-secret`). Note the floor: `GetRelativePath` is .NET Core 2.0 / .NET Standard 2.1 and **does not exist on .NET Framework**, so a Framework target needs a `GetFullPath` comparison instead
- Match the platform's own comparison. `GetRelativePath` internally uses `OrdinalIgnoreCase` on Windows and macOS and `Ordinal` on Linux; a hand-written comparison should do the same, since bare `Ordinal` on Windows treats `C:\App\Docs` and `c:\app\docs` as different paths that name the same directory
- Where only a filename is expected, require `Path.GetFileName(name) == name` **and** screen `Path.GetInvalidFileNameChars()`. The equality test alone is not enough: separators are the only thing it looks at, so `report.txt:hidden` passes it. The character screen catches the colon, but only on Windows - the Unix array is just `{'\0', '/'}`, so an NTFS alternate-data-stream name is screened only where NTFS is
- `Path.GetFullPath()` does not follow symbolic links or junctions; where reparse-point escapes are in scope, check `File.GetAttributes()` for `FileAttributes.ReparsePoint` or resolve with `FileInfo.ResolveLinkTarget(returnFinalTarget: true)` (**.NET 6+**, no .NET Framework equivalent) and re-verify containment
- Confirm the target is a regular file rather than a directory before serving it, and pass the canonical path - not the original input - to the file API

## Taint Sinks

`Path.Combine()` with unvalidated input, `File.ReadAllBytes()`, `File.Open()`, `PhysicalFile()`, `Directory.GetFiles()`

## Remediation Steps

- Locate - find path comparisons or containment checks (`StartsWith`, `==`, `Contains`) applied to a path built from route values, query strings, or form data
- Trace data flow - follow the value from the action parameter through `Path.Combine()` to the comparison and then to the file API, noting whether the compared value and the opened value are the same variable
- Replace the unsafe pattern - resolve the base directory once with `Path.GetFullPath()` into a `static readonly` field, join with `Path.Join()`, canonicalize the result, and compare with `Path.GetRelativePath()`
- Bind, encode, validate, or authorize - reject names containing separators or invalid filename characters before joining, and apply an extension allowlist where only certain types are legitimate
- Break taint after allowlist validation - pass the canonical path variable to `PhysicalFile()`/`File.Open()`, never the request value. `PhysicalFile()` applies no containment of its own; it checks only that the path is rooted
- Harden configuration - check `FileAttributes.ReparsePoint` where symlinks or junctions may exist in the served tree, and restrict the process account's filesystem permissions to that tree
- Test - assert equivalent spellings reach the same decision, including the two that Windows normalization actually changes: a trailing dot or space is stripped *unless* the path ends in a separator, so a name written with a trailing space then a backslash keeps that space while the same name without the backslash loses it. Confirm `..\..\` payloads are refused and a legitimate file still downloads
