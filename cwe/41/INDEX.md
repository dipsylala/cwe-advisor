# CWE-41: Improper Resolution of Path Equivalence

## LLM Guidance

Path equivalence issues occur when a security check compares or validates a path string without first resolving it to canonical form, so semantically identical paths that differ only in encoding, trailing separators, case, `.`/`..` segments, or symbolic links bypass the check. This differs from path traversal: the vulnerable step is the comparison logic itself, not `../` sequences reaching a sink. The fix is to canonicalize both sides of any path comparison before applying access control or containment checks.

## Key Principles

- Canonicalize (resolve symlinks, `.`/`..`, encoding, and case as appropriate for the OS) before any comparison or validation, never after
- Never compare raw path strings for access-control decisions; always compare canonical forms
- Use path-component-aware containment checks against an allowed base directory, not raw string-prefix matching, to avoid sibling-directory bypasses
- Treat all externally influenced path input as untrusted, including filenames from uploads, headers, and API parameters
- Normalize exactly once, immediately before the security check, and reuse that normalized value for the subsequent operation to avoid re-normalization drift
- Apply defence-in-depth: least-privilege filesystem permissions and logging of rejected path-equivalence attempts

## Remediation Steps

- Locate - find where a path is compared, validated, or checked for containment against an allowed location
- Trace data flow - follow the path value from its untrusted source to the comparison and then to the eventual file operation, noting every transformation
- Identify the unsafe pattern - string equality or prefix checks performed on a raw, non-canonical path, or checks performed before normalization
- Replace with the safe pattern - resolve the path to its canonical absolute form first, then perform component-aware containment or equality checks against the canonical allowed path
- Break taint after allowlist validation - once the canonical path is confirmed inside the allowed base, use that canonical value, not the original input, for the file operation
- Add secondary controls - reject ambiguous or doubly-encoded input outright, and restrict the process's filesystem permissions to the intended directory tree
- Test - verify with equivalent representations of the same path (trailing separators, `.` segments, alternate case, symlinks, encoded separators) that all resolve to the same accept/reject decision
