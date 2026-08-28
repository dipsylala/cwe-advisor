# CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

## LLM Guidance

Path Traversal occurs when applications use user-supplied input to construct file paths without proper validation, allowing attackers to access files outside the intended directory using sequences like `../`. The core fix is to never allow untrusted input to directly control filesystem paths; always canonicalize paths and enforce containment within an allowlisted root directory. Where the weakness is which file the user may select rather than escaping the directory, use CWE-73; where validation is bypassed by equivalent spellings of the same path, use CWE-41.

## Key Principles

- Reject direct user input in paths: Never use untrusted data directly as file paths or path components
- Validate the value the sink will receive, not the raw request string: web frameworks percent-decode once before your code sees it, so a second decode manufactures traversal from an inert literal (`%252e%252e%252f` becomes `../`), while a filter applied to the undecoded form never fires
- Unicode normalisation is not a traversal control: the filesystem does not read U+FF0F FULLWIDTH SOLIDUS or U+2215 DIVISION SLASH as separators, and NFC leaves both unchanged - they are ordinary filename characters, handled by canonicalize-then-contain rather than by character filtering
- Canonicalize before validation: Resolve symlinks and relative paths (`.`, `..`) to absolute form before security checks
- Enforce allowlist containment: Verify canonicalized paths stay within permitted root directories using path-component-aware comparison (`Path.is_relative_to()`, `Path.startsWith()` on `java.nio.file.Path`), not a raw string prefix - `/app/uploads-secret` passes a `startsWith("/app/uploads")` string test
- Check the value you will actually use: resolve once into a variable and pass that same variable to the file operation, rather than validating the raw input and re-deriving the path separately for the open
- Treat archive extraction as a distinct sink: Zip/tar/etc. entry names are untrusted input - canonicalize each entry's computed target path and verify it stays within the extraction base directory before writing (Zip Slip), exactly like any other path-traversal sink
- Use indirect references: Map user input to internal IDs, then lookup actual paths from a secure database or allowlist
- Validate after canonicalization: String filtering alone fails; validate the resolved absolute path

## Remediation Steps

- Trace data flow - Identify where file path data enters (user input, APIs, databases), how it's constructed (string concatenation with `/` or `\`), and where it reaches a file operation (see the language-specific guidance's Taint Sinks for concrete function names)
- Implement indirect references - Replace direct path usage with user-provided IDs/names that map to system-controlled paths via database lookup or allowlist
- Decode at most once - use the value the framework already decoded and add no second pass before filtering or path construction
- Canonicalize paths - Convert all paths to absolute canonical form, resolving symlinks and relative references before any validation
- Enforce root containment - After canonicalization, verify the resolved path equals the approved root or is inside it by path component; if a string comparison is unavoidable, append the separator to the base first
- Reject, do not strip - refuse input containing `..`, absolute paths, or encoded/Unicode traversal sequences rather than removing them; a single non-recursive replacement turns `....//` into `../` and a silent strip hides the attempt from logs. Denylisting is a secondary control - canonicalize-then-contain is the fix
- Apply defence in depth - Combine indirect references, canonicalization, allowlist validation, and filesystem permissions as layered controls
