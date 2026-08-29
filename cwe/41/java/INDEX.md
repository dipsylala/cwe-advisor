# CWE-41: Improper Resolution of Path Equivalence - Java

## LLM Guidance

In Java this appears when a path built with `java.io.File` and string concatenation is checked with `exists()` or a string comparison instead of being canonicalized first. Methods that operate only on the abstract pathname make no filesystem call, so a link planted inside the served directory points wherever the attacker chose while every check on the path string still passes. The fix is to normalize, check containment, then canonicalize with `Path.toRealPath()` and check containment again on the resolved path.

## Key Principles

- Compare `java.nio.file.Path` objects with `Path.startsWith(Path)`, which is component-aware. The bypass is `java.lang.String.startsWith` on the path *strings*, which accepts a sibling such as `/app/uploads-backup` - note that `Path.startsWith(String)` is not that method: it converts the argument to a `Path` and behaves exactly like the `Path` overload
- `Path.normalize()` is textual - its javadoc warns that eliminating `..` and a preceding name "may result in the path that locates a different file than the original path" when that name is a symbolic link. `File.getAbsolutePath()` only makes a relative path absolute against `user.dir`; it resolves no `.`, `..` or links
- `toRealPath()` resolves symbolic links by default and is the dependable canonicalizer. `File.getCanonicalPath()` is the weaker guarantee: its javadoc says canonical form is "system-dependent" and "*typically* involves" resolving links, and through JDK 24 it scoped that clause to "(on UNIX platforms)" - the parenthetical was only dropped in JDK 25. Prefer `toRealPath()`
- Check containment twice: on the normalized path before resolving, so a traversal is refused even when the target does not exist, and on the `toRealPath()` result, so a symlink escape is caught
- Resolve the base directory with `toRealPath()` at request time rather than in a static initializer, so a missing directory produces a handled error instead of a class-initialization failure
- Where only a filename is expected, reject input containing a path separator. `getNameCount() == 1` is a weak substitute: it is also 1 for the empty path, and it does not exclude a Windows prefix such as `C:foo`
- Confirm the target with `Files.isRegularFile()` before serving, so directories and special files are refused - but note it returns `false` for an I/O error too, so where the two must be distinguished, read `BasicFileAttributes` instead
- Prefer `Path.of()` over `Paths.get()`: the `Paths` javadoc carries an `@apiNote` recommending it "as this class may be deprecated in a future release" (JDK 11+). Behaviour is identical, so this is hygiene, not a fix
- Spring's `FileSystemResource` applies no containment: it builds its `File` from the raw constructor argument, and the one primitive it does use elsewhere, `StringUtils.cleanPath`, carries Spring's own note that it "should not be depended upon in a security context"
- Keep the served directory unwritable by the application account. The gap between `toRealPath()` and the open is a path-swap race; `SecureDirectoryStream` is the JDK's race-free option where the platform supports it, and ordinary check-then-open cannot close it

## Taint Sinks

`new File(path)`, `Path.of()`/`Paths.get()`, `Files.newInputStream()`, `Files.readAllBytes()`, `new FileInputStream()`, `FileSystemResource`

## Remediation Steps

- Locate - find where `@PathVariable`, `@RequestParam`, or `request.getParameter()` is concatenated into a path or compared against an allowed location
- Trace data flow - follow the value through `resolve()` or concatenation to the check and then to the stream or `Resource` construction
- Replace the unsafe pattern - resolve against the real base directory, `normalize()`, verify `startsWith(allowedDir)`, then `toRealPath()` and verify `startsWith(allowedDir)` again
- Bind, encode, validate, or authorize - reject filenames containing separators before resolving, and apply an extension allowlist where only certain types are legitimate
- Break taint after allowlist validation - pass the `toRealPath()` result to the file operation, never the original parameter
- Harden configuration - restrict filesystem permissions on the served directory and ensure the application cannot create symbolic links inside it
- Test - assert equivalent spellings (`dir`, `dir/`, `dir/.`, `dir//`) reach the same decision, that a symlink planted in the base directory pointing at `/etc/passwd` is refused, and that a legitimate file still downloads
