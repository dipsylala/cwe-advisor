# CWE-90: Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection') - C#

## LLM Guidance

LDAP Injection occurs when untrusted data is used to construct LDAP queries without proper encoding, allowing attackers to manipulate LDAP searches and access unauthorized data. The core fix involves strict allowlist validation of input (e.g., alphanumeric usernames only) and escaping the LDAP filter metacharacters (`*`, `(`, `)`, `\`, NUL). Never construct Distinguished Names (DNs) directly from user input-instead, search by attribute and use the returned DN for subsequent operations.

## Key Principles

- Validate with strict allowlists - Restrict input to expected patterns before any LDAP operations
- Escape LDAP metacharacters - Encode `*`, `(`, `)`, `\` and NUL when user input must appear in
  filters, using the RFC 4515 hex forms `\2a`, `\28`, `\29`, `\5c` and `\00`. RFC 4515 defines no
  escape for `/`, so do not add one; when escaping by sequential replacement, replace `\` first or the sequences inserted afterwards are escaped a second time
- Search-then-use pattern - Query by safe attribute, retrieve the object's DN, use that DN for further operations
- Avoid DN construction - Never concatenate user input into Distinguished Names or filter strings
- Principle of least privilege - Use service accounts with minimal LDAP permissions

## Taint Sinks

`DirectorySearcher.Filter` built by concatenation, `DirectoryEntry.Path` built from user input, `String.Format()` into an LDAP filter

## Remediation Steps

- Apply regex allowlist validation to usernames/inputs - `^[a-zA-Z0-9._-]{3,64}$`
- Escape LDAP special characters if validation isn't feasible - `*`, `(`, `)`, `\` and null bytes
- Use `DirectorySearcher.Filter` with escaped values instead of string concatenation
- For authentication, search by `sAMAccountName`, retrieve the object, then use its `Path` property
- Never build LDAP filter strings with `String.Format()` or interpolation on raw user input
- Test with a bare `*` and with `admin*`, which are valid filter syntax and so actually reach the
  server; `*)(objectClass=*)` is rejected by the client's own parser and proves nothing either way
