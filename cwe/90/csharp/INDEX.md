# CWE-90: Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection') - C#

## LLM Guidance

LDAP Injection occurs when untrusted data is used to construct LDAP queries without proper encoding, allowing attackers to manipulate LDAP searches and access unauthorized data. The core fix is escaping the LDAP filter metacharacters, or a typed filter API; an allowlist on the value is a separate decision, for where the application defines its format. The metacharacters are (`*`, `(`, `)`, `\`, NUL). Never construct Distinguished Names (DNs) directly from user input-instead, search by attribute and use the returned DN for subsequent operations.

## Key Principles

- Add an allowlist only where the application defines the value's format (a username policy), and state what it rejects; escaping alone closes the injection, and a pattern chosen for security alone rejects legitimate values
- Escape LDAP metacharacters - Encode `*`, `(`, `)`, `\` and NUL when user input must appear in
  filters, using the RFC 4515 hex forms `\2a`, `\28`, `\29`, `\5c` and `\00`. RFC 4515 defines no
  escape for `/`, so do not add one; when escaping by sequential replacement, replace `\` first or the sequences inserted afterwards are escaped a second time
- Search-then-use pattern - Query by safe attribute, retrieve the object's DN, use that DN for further operations
- Avoid DN construction - Never concatenate user input into Distinguished Names or filter strings
- Principle of least privilege - Use service accounts with minimal LDAP permissions

- A distinguished name uses a different escape set from a filter: RFC 4514 gives structural meaning to
  `,`, `+`, `"`, `\`, `<`, `>`, `;` and `=`, and additionally to a leading `#` and to a space at
  either end, which the DN parser discards unless escaped. Trimming or stripping those instead of
  escaping them quietly changes which object the DN addresses

## Taint Sinks

`DirectorySearcher.Filter` built by concatenation, `DirectoryEntry.Path` built from user input, `String.Format()` into an LDAP filter

## Remediation Steps

- Where the application has a username policy, enforce it before the search with a pattern that matches that policy (`^[a-zA-Z0-9._-]{3,64}$` only where usernames are defined that way) and say so in the write-up; do not invent one for the fix
- Escape LDAP special characters - `*`, `(`, `)`, `\` and null bytes - whether or not a format check exists
- Use `DirectorySearcher.Filter` with escaped values instead of string concatenation
- For authentication, search by `sAMAccountName`, retrieve the object, then use its `Path` property
- Never build LDAP filter strings with `String.Format()` or interpolation on raw user input
- Test with a bare `*` and with `admin*`, which are valid filter syntax and so actually reach the
  server; `*)(objectClass=*)` is rejected by the client's own parser and proves nothing either way
