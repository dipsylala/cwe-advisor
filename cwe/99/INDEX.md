# CWE-99: Improper Control of Resource Identifiers ('Resource Injection')

## LLM Guidance

Resource Injection occurs when untrusted input selects system resources (files, ports, class names, URLs) without validation, allowing attackers to manipulate which resources the application accesses. The core fix is to never let untrusted input directly select resources; instead, use allowlisted mappings and canonical validation so only permitted resources are reachable. MITRE marks this ID Allowed-with-Review because it is a Class: almost every finding has a more specific entry, chosen by the sink rather than by anything visible at the reported line.

## Key Principles

- Route by sink before remediating: a file path is CWE-22 (escapes the directory) or CWE-73 (names the file at all); a class or method resolved by reflection is CWE-470; a URL the *server* fetches is CWE-918; a URL the *browser* is sent to is CWE-601; a database name, connection string, or other setting is CWE-15. A port chosen directly by a request is the case this entry terminates
- Never let untrusted input select resources by name or path directly
- Canonicalize all resource identifiers (resolve paths, normalize names) before validation
- Map user-controlled input to allowlisted resources using indirect references
- Validate against strict allowlists of permitted resources, not denylists
- Use resource IDs or tokens that map server-side to actual resource locations
- Bind each allowlisted key to the operation it selects rather than to a name the framework then resolves - and where a class is loaded, load it without running static initializers, which execute before any type check can reject it
- Derive the resource from the session or the server's own configuration where possible, rather than accepting a value and inspecting it

## Remediation Steps

- Identify sources - Find all untrusted data sources (HTTP parameters, external APIs, databases, file uploads, network requests)
- Trace resource selection - Follow how untrusted data flows to resource access points (file paths, port numbers, class names, URLs)
- Locate sinks - Identify where resources are accessed (file operations, network connections, class loading, database connections)
- Detect missing validation - Find resource selection without allowlist checks or canonicalization
- Implement allowlists - Create strict allowlists of permitted resources and validate all input against them before access
- Use indirect references - Replace direct resource names with IDs or tokens mapped server-side to actual resources
