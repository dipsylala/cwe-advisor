# CWE-538: Insertion of Sensitive Information into Externally-Accessible File or Directory

## LLM Guidance

This weakness occurs when sensitive data (credentials, backups, internal configuration, source code, logs) is placed in a location that users outside the intended trust boundary can reach: a web-served directory, a public storage bucket, or a shared file path. The root cause is treating "not linked" or "not documented" as equivalent to "not accessible" - anything under an externally-reachable root is reachable regardless of discoverability. The fix is to relocate sensitive content outside any exposed root, or to apply explicit access control if it must remain there.

## Key Principles

- Never place credentials, backups, source, or internal configuration inside a publicly-served directory or bucket
- Treat every path under an externally-accessible root as reachable, whether or not it is linked
- Apply authentication or authorization before content becomes reachable, not as an afterthought
- Keep storage boundaries separate from serving boundaries so only intentionally-published files are servable
- Return generic error messages and avoid leaking internal file paths through errors, headers, or metadata
- Audit build and deployment output for stray sensitive files: backups, VCS directories, editor swap files

## Remediation Steps

- Locate - identify the sensitive artifact (credential, backup, config, log, source file) and its path relative to any externally-accessible root
- Trace exposure - determine how an outside user could reach that path (direct request, listing, misconfigured serving rule, symlink)
- Identify the unsafe pattern - sensitive content stored inside, or reachable from, a served directory or public storage location
- Replace with the safe pattern - move the content outside any exposed root, or add authentication and authorization scoped to that specific path
- Remove indirect exposure vectors - strip internal paths and identifying details from error messages, headers, and metadata
- Add secondary controls - deny access to known sensitive file patterns and extensions at the server or gateway layer
- Test - request the expected sensitive paths directly and confirm a generic denied/not-found response, and confirm no sensitive files ship in build or deploy artifacts
