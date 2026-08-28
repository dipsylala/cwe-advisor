# CWE-41: Improper Resolution of Path Equivalence - Java

## LLM Guidance

In Java this appears when a path built with `java.io.File` and string concatenation is checked with `exists()` or a string comparison instead of being canonicalized first. The legacy `File` API does not resolve symbolic links, so a link planted inside the served directory points wherever the attacker chose while every check on the path string still passes. The fix is to normalize, check containment, then canonicalize with `Path.toRealPath()` and check containment again on the resolved path.

## Key Principles

- Compare `java.nio.file.Path` objects with `Path.startsWith(Path)`, which is component-aware; `canonicalPath.startsWith(baseDir)` on the *strings* accepts a sibling such as `/app/uploads-backup`
- `Path.normalize()` is textual and `File.getAbsolutePath()` resolves nothing - only `toRealPath()` and `File.getCanonicalFile()` follow symbolic links
- Check containment twice: on the normalized path before resolving, so a traversal is refused even when the target does not exist, and on the `toRealPath()` result, so a symlink escape is caught
- Resolve the base directory with `toRealPath()` at request time rather than in a static initializer, so a missing directory produces a handled error instead of a class-initialization failure
- Where only a filename is expected, reject input containing a path separator, or require `Paths.get(filename).getNameCount() == 1`
- Confirm the target with `Files.isRegularFile()` before serving, so directories and special files are refused
- Keep the served directory unwritable by the application account; the gap between `toRealPath()` and the open is a path-swap race that application code cannot close

## Taint Sinks

`new File(path)`, `Paths.get()`, `Files.newInputStream()`, `Files.readAllBytes()`, `new FileInputStream()`, `FileSystemResource`

## Remediation Steps

- Locate - find where `@PathVariable`, `@RequestParam`, or `request.getParameter()` is concatenated into a path or compared against an allowed location
- Trace data flow - follow the value through `resolve()` or concatenation to the check and then to the stream or `Resource` construction
- Replace the unsafe pattern - resolve against the real base directory, `normalize()`, verify `startsWith(allowedDir)`, then `toRealPath()` and verify `startsWith(allowedDir)` again
- Bind, encode, validate, or authorize - reject filenames containing separators before resolving, and apply an extension allowlist where only certain types are legitimate
- Break taint after allowlist validation - pass the `toRealPath()` result to the file operation, never the original parameter
- Harden configuration - restrict filesystem permissions on the served directory and ensure the application cannot create symbolic links inside it
- Test - assert equivalent spellings (`dir`, `dir/`, `dir/.`, `dir//`) reach the same decision, that a symlink planted in the base directory pointing at `/etc/passwd` is refused, and that a legitimate file still downloads
