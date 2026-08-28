# CWE-90: Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection') - Python

## LLM Guidance

LDAP Injection occurs when untrusted user input is concatenated into LDAP queries without proper sanitization, allowing attackers to manipulate queries to bypass authentication, escalate privileges, or extract sensitive directory data.

**Primary Defence:** Use `ldap3` filter escaping with strict allowlists for user-controlled filter values and DN components. LDAP filters are not SQL-style prepared statements, so never concatenate raw user input into filter strings.

## Key Principles

- Use `ldap3` with escaped filter values instead of raw string concatenation
- Escape all special LDAP characters in user input using `ldap3.utils.conv.escape_filter_chars()`
- Apply allowlist validation on user input before query construction
- Implement least-privilege access for LDAP service accounts
- Use DN (Distinguished Name) sanitization for attribute values

## Taint Sinks

`Connection.search()` (ldap3) with a concatenated filter string

## Remediation Steps

- Replace string concatenation with escaped filter construction
- Apply `escape_filter_chars()` to all user-controlled variables in LDAP filters
- Validate input against expected patterns (e.g., alphanumeric usernames)
- Review LDAP query logging to detect injection attempts
- Test filters with a bare `*` and `admin*`, which are valid syntax and reach the server;
  `*)(objectClass=*)` and `admin)(&(password=*)` are rejected by the client parser before any request
  is sent, so they cannot tell a working fix from a broken filter
- Restrict LDAP bind account permissions to minimum required scope
