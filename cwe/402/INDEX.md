# CWE-402: Transmission of Private Resources into a New Sphere ('Resource Leak')

## LLM Guidance

This weakness occurs when a private resource - a file outside the intended public directory, an internal data structure, a full database record, an internal object reference, or a raw handle - crosses a trust boundary and becomes reachable by a less-privileged party such as an external caller or a different user. It differs from a memory or handle exhaustion leak: here the "resource" is private data or a reference to it, and the "leak" is exposure across a trust boundary rather than a failure to release memory. Fix it by explicitly filtering what crosses the boundary: transmit only an allowlisted, minimal representation of the resource rather than the resource itself or its raw internal reference.

## Key Principles

- Never pass an internal object, full record, raw file path, or resource handle directly across a trust boundary; construct an explicit, minimal representation for the receiving sphere
- Default-deny: only fields, files, or resources on an explicit allowlist should ever cross into a less-trusted context
- Enforce boundary checks (canonicalize and confirm the resource resolves inside an allowed root or scope) before granting cross-boundary access to file-like resources
- Treat error messages, logs, and debug output as transmission points too; ensure they do not include internal object contents reaching a lower-privileged recipient
- Apply the same filtering consistently at every exit point - API responses, exports, logs, callbacks - not only the one identified by a scanner
- Require a server-side authorization check confirming the requester is entitled to the specific resource, independent of the allowlist filtering step

## Remediation Steps

- Locate - Identify the point where an internal resource (object, file, record, handle) is returned, serialized, or otherwise made available to a less-trusted caller
- Trace data flow - Follow the resource from its internal representation to the boundary-crossing point (API response, exported file, IPC message, log entry)
- Identify the unsafe pattern - Look for direct serialization of internal objects or entities, unrestricted file path resolution, or resource references passed by identifier without a scope check
- Replace with the safe pattern - Construct a minimal, purpose-built representation (allowlisted fields, resolved-and-verified file path) instead of exposing the internal resource directly
- Enforce boundary and authorization checks - Confirm the resolved resource is within the allowed scope and that the requester is authorized for that specific resource
- Add secondary controls - Suppress internal resource details in error messages and logs reaching the lower-trust sphere
- Test - Attempt to access resources outside the intended scope (path traversal, sequential identifier enumeration, oversized field disclosure) and confirm they are rejected or filtered
