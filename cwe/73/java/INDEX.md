# CWE-73: External Control of File Name or Path - Java

## LLM Guidance

External control of file names or paths occurs when untrusted input (HTTP requests, uploads, APIs) constructs file system paths without validation in Java applications. Java's `File`, `Path`, and I/O classes lack built-in path traversal protection, making applications vulnerable when user input directly influences file operations.

## Key Principles

- Validate all file names/paths against an allowlist of permitted values or patterns
- Decode and Unicode-normalise input before filtering: use `URLDecoder.decode()` and `Normalizer.normalize(input, Form.NFC)` - overlong UTF-8 sequences and Unicode full-width separators bypass checks on raw strings. Decode exactly once: Spring already decodes request parameters before the handler runs, so a handler that denylists `..` and then calls `URLDecoder.decode()` again on its own lets a double-encoded `%252e%252e%252f` pass the check and become `../../` only on the second pass
- Use canonical paths to resolve symbolic links and relative references (`.`, `..`) - `Paths.get(input).normalize()` is purely lexical and does not touch the filesystem, so a symlink inside the base directory pointing outside it survives `normalize()` untouched; only `toRealPath()`/`getCanonicalPath()` resolve it. Spring's `StringUtils.cleanPath()` is display/path-tidying hygiene, not a containment boundary - it does not confirm the result stays inside any directory
- Restrict file operations to a defined base directory using path normalization
- Never concatenate user input directly into file paths
- Reject file names containing a path separator or traversal sequence rather than stripping them - a strip is bypassable, destroys legitimate names, and hides the attempt from logs, and reject an embedded null byte (`\0`) on the same grounds
- Where a bare filename is expected, take `Paths.get(name).getFileName()` as a *check* (`getFileName().toString().equals(name)`), not as a cleaner; on Unix `Paths.get("..\\..\\etc\\passwd").getFileName()` returns the whole string because backslash is not a separator there
- Compare with `Path.startsWith(Path)` on resolved `Path` objects, not `canonicalPath.toString().startsWith(baseDirectory)` - the string form accepts a sibling such as `/app/uploads-backup`; once contained, confirm the target with `Files.isRegularFile()` so directories and special files are refused

## Taint Sinks

`new File()`, `Files.readAllBytes()`, `Paths.get()`, `FileReader`/`FileWriter` with unvalidated input

## Remediation Steps

- Identify untrusted sources - Locate where external data enters (`request.getParameter()`, `@PathVariable`, `MultipartFile.getOriginalFilename()`, headers, JSON/XML fields)
- Trace to file operations - Find sinks using `new File()`, `Files.readAllBytes()`, `Paths.get()`, `FileReader/Writer`, or I/O constructors
- Validate against allowlist - Check file names/extensions against permitted values before use
- Decode and normalise - Call `URLDecoder.decode(input, StandardCharsets.UTF_8)` and `Normalizer.normalize(decoded, Form.NFC)` before any character filtering
- Canonicalize paths - Use `File.getCanonicalPath()` (succeeds whether or not the file exists) for a write target that may not exist yet, or `Path.toRealPath()` for a read target, which throws `NoSuchFileException` if the file is absent - passing `LinkOption.NOFOLLOW_LINKS` skips symlink resolution but does not remove that existence requirement
- Enforce base directory - Verify canonical path starts with approved base directory
- Reject invalid input - Return error for paths failing validation; never allow fallback to user input
- Authorize separately - containment inside the base directory is not permission to read that file; check ownership or role before `Files.newInputStream()`, and do not treat `Files.exists()` as an access decision
