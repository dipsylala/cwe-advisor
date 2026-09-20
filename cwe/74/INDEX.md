# CWE-74: Improper Neutralization of Special Elements in Output Used by a Downstream Component ('Injection')

## LLM Guidance

MITRE's broad parent for injection, and discouraged as a mapping target. Where the sink is known, use the matching child - SQL, command, XSS, LDAP, XML, CRLF, code, CSV/formula, or query-logic injection - since the correct primary defence depends entirely on which interpreter receives the data. Use this page only where a finding is reported generically as "injection" with no identified sink.

## Key Principles

- Identify the downstream interpreter first; the correct primary defence depends entirely on which sink receives the data
- Prefer a structured API that keeps data separate from syntax (parameterized queries, parameterized process execution, auto-escaping templates, builder APIs) over any form of manual escaping
- Never build interpreter input by concatenating or formatting untrusted data directly into a command, query, or document string
- Treat all externally influenced input as untrusted regardless of source, including upstream service responses and file contents
- Use allowlist validation as a secondary layer (type, format, length, enumerated values), never as the sole defence
- Apply least privilege to the account or process executing the interpreter to limit the impact of any missed case

## Remediation Steps

- Locate - identify the untrusted source and the downstream interpreter that ultimately consumes the built string
- Trace data flow - follow the value through concatenation, formatting, or template interpolation until it reaches the interpreter call
- Identify the unsafe pattern - name the specific injection subtype (SQL, command, XSS, LDAP, XML, CRLF, code, CSV/formula, NoSQL) so the matching dedicated guidance can be applied
- Replace with the safe pattern - adopt the sink-specific structured API for that subtype rather than a generic escaping routine
- Break taint after allowlist validation - when input is checked against an allowlist, pass the allowlist-selected value onward, not the original string
- Add secondary controls - layer input validation, least-privilege interpreter accounts, and output encoding where relevant
- Test - submit the interpreter's own metacharacters and confirm they are treated as literal data, then confirm legitimate input still functions correctly
