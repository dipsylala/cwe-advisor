# CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') - Java

## LLM Guidance

Path Traversal occurs when user input constructs file paths without validation, allowing attackers to use `../` sequences or absolute paths to access files outside the intended directory. This can expose sensitive files like `/etc/passwd` or `WEB-INF/web.xml`.

**Primary Defence:** Use indirect reference mapping (map IDs to filenames), or resolve the candidate with `toRealPath()` and confirm the result is inside the base directory with `Path.startsWith(Path)`.

## Key Principles

- Use indirect reference maps instead of accepting filenames directly from users
- Do not re-decode: `request.getParameter()`, `@RequestParam` and model binding already return percent-decoded values, so a further `URLDecoder.decode()` turns the inert literal `%2e%2e%2f` into `../`; `URLDecoder` also maps `+` to a space, corrupting legitimate filenames
- Validate canonical paths remain within the intended base directory
- Compare `java.nio.file.Path` objects with `Path.startsWith(Path)` (or `File.getCanonicalPath()` against a separator-terminated base) - `canonicalPath.startsWith(baseDir)` on the *strings* accepts a sibling such as `/app/uploads-backup`
- `Path.normalize()` is textual and `getAbsolutePath()` resolves nothing; only `toRealPath()`/`getCanonicalFile()` follow symbolic links
- `toRealPath()` throws `NoSuchFileException` when the target does not exist, so it cannot validate an upload destination - canonicalize the parent directory instead, check that with `startsWith`, and require the supplied name to be a single component by rejecting anything where `Paths.get(name).getFileName().toString()` differs from `name`
- Reject paths containing traversal sequences (`../`, `..\\`) or null bytes
- Use allowlists for permitted file extensions and directories
- Avoid constructing paths from untrusted input when possible
- Archive extraction (Zip Slip): treat `ZipEntry.getName()` from `java.util.zip.ZipInputStream` (or Apache Commons Compress) as untrusted - resolve it against the destination directory and verify containment with `Path.startsWith()` after `toRealPath()`/normalization, the same pattern used above, before extracting

## Taint Sinks

`new File(path)`, `Files.newInputStream()`, `new FileInputStream()`, `ZipEntry.getName()` (Zip Slip)

## Remediation Steps

- Implement indirect object references (user provides ID, application maps to filename)
- Validate the value the container already decoded - add no second `URLDecoder.decode()` pass, and do not rely on `Normalizer` to neutralise separators
- Canonicalize with `Path.toRealPath()` or `File.getCanonicalFile()`, which follow symbolic links; `normalize()` only rewrites the string and leaves a planted link in place
- Verify containment by comparing `Path` objects - `resolved.startsWith(base)` with `base` canonicalized the same way - never the two as strings
- Reject requests with traversal sequences, absolute paths, or suspicious characters
- Apply allowlist validation for file extensions if direct input is unavoidable
- Use OS/container sandboxing and filesystem permissions to restrict file access
