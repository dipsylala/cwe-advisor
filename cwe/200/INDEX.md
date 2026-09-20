# CWE-200: Exposure of Sensitive Information to an Unauthorized Actor

## LLM Guidance

Information exposure occurs when applications reveal sensitive data to unauthorized users through error messages, APIs, configuration files, or exposed resources. Information that appears harmless individually (user enumeration, timing differences, stack traces) can be combined to enable sophisticated attacks like account compromise. Never return sensitive or internal information to clients unless explicitly required for their authorized function. MITRE marks CWE-200 Discouraged for mapping, because confidentiality loss is an impact rather than a root cause, so re-file the finding under whatever error disclosed the data. Treat this entry as a router: where the finding names a mechanism, use that page instead - response or API payload (CWE-201), error message or stack trace (CWE-209), debugging code (CWE-215), personal information (CWE-359), system information (CWE-497), log file (CWE-532), or a backup/config/VCS file reachable in the webroot (CWE-538).

## Key Principles

- Use allowlisted exposure model: construct responses from explicitly approved data, not internal state
- Sanitize all user-facing outputs including error messages, API responses, headers, and logs
- Implement generic error handling that reveals no internal system details
- Validate what information each user role legitimately needs before exposing it
- Assume attackers will combine multiple small leaks to build attack chains
- Build the response from an allowlist *before* serializing, never by serializing an internal object and redacting afterwards - a field added to the record later ships exposed by default, and there is no statement of intent for a reviewer to check
- Where the request names a guessable resource, return identical responses for "not found" and "not authorized" - same status, same body, and where the check is measurable the same timing - since a 403/404 split enumerates valid resources without disclosing any data. A role or permission gate on an endpoint that is not itself a secret answers 403; the identical-response rule is for the object-level case, matching CWE-862 and CWE-863
- A masked or truncated value is not automatically safe: judge what the remaining fragment enables (a last-four, an unsalted hash, a truncated token) rather than accepting that it looks redacted

## Remediation Steps

- Review flaw details to identify the specific file, line number, and code pattern exposing information
- Identify what sensitive data is leaking - stack traces, credentials, file paths, user data, internal IDs, system details
- Trace the data flow from source to exposure point through error handlers, API responses, logs, or HTTP headers
- Determine the audience - who can access this information (authenticated users, anonymous users, public internet)
- Replace detailed error messages with generic user-facing messages; log full details server-side only
- Construct the response from an explicit field allowlist - a DTO or serializer naming the fields to include - rather than serializing the internal object and stripping fields from it
- Load the child entry for the mechanism named in the finding, and apply its fix; this entry carries only what the family shares
- Test - re-trigger the original condition and assert the leaked field or message is absent from the response, the headers and the logs; where the finding was an enumeration oracle, assert the not-found and not-authorized responses are byte-identical
