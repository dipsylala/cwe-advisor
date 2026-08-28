# CWE-90: Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection')

## LLM Guidance

LDAP Injection occurs when untrusted user input is used to construct LDAP queries without proper validation or escaping, allowing attackers to modify queries and access or manipulate directory data. Never concatenate untrusted input into LDAP filters; use safe LDAP APIs and strict allowlists. The filter is parsed as an expression tree, so an injected `)` ends the term the value was interpolated into and `(` starts another, while a bare `*` turns an equality test into a match-everything wildcard. CWE-90 is a child of CWE-943; use that entry for the general structured-query defence and this one for the LDAP-specific rules.

## Key Principles

- Use LDAP filter builders or RFC4515/RFC4514 escaping to separate query structure from user data
- Filter escaping (RFC 4515) and DN escaping (RFC 4514) cover different character sets - a value escaped for one context still carries unescaped metacharacters for the other, so never reuse one escaping for the other
- Prefer search-then-use-the-returned-DN over building a DN from input: escaping reduces the risk, but letting the directory hand you the DN removes the injection point
- Escape special LDAP characters using framework-specific encoding functions, covering the whole set (`*`, `(`, `)`, backslash, NUL) - a partial denylist still leaves enough syntax to close one clause and open another
- Apply strict allowlist validation for filter components
- Minimize search scope and restrict returned attributes
- Implement defence-in-depth with input validation, output encoding, and least privilege

## Remediation Steps

- Trace the vulnerability - Identify the source of untrusted data and trace its flow to the LDAP query construction sink
- Replace string concatenation - Use LDAP filter builders or escape filter values and DNs with LDAP-specific escaping APIs
- Escape user input - Apply LDAP-specific escaping for special characters - `*`, `(`, `)`, `\`, `NUL`, `/`
- Validate with allowlists - Restrict input to known-safe patterns using allowlists for attribute names and values
- Limit query scope - Use specific base DNs and restrict search depth to minimize exposure
- Apply least privilege to the bind account - escaping is the control, but a read-only, narrowly scoped bind account limits what any missed field can reach
- Test thoroughly - Verify fixes with injection payloads like `*)(objectClass=*)` and review authentication/authorization logic
