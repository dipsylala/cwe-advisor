# CWE-90: Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection') - JavaScript

## LLM Guidance

LDAP Injection occurs when untrusted user input is concatenated into LDAP queries without proper sanitization, allowing attackers to modify query logic. This can lead to authentication bypass, unauthorized data access, or privilege escalation in applications using LDAP for directory services. The core fix is to use LDAP filter builders or RFC4515 escaping with strict input validation and allowlisting.

## Key Principles

- Build the filter as an object, not a string. `ldapjs` 3.x exposes its filter classes - `new ldap.EqualityFilter({ attribute: 'uid', value: userInput })`, `AndFilter`, `SubstringFilter` and the rest from `@ldapjs/filter` 2.x - and their `toString()` escapes the value (`admin)(|(objectClass=*` becomes `admin\29\28|\28objectClass=\2a`); pass the object as `client.search(base, { filter })`. Where a filter must stay a string, `ldap-escape` 2.0.6 gives the same escaping as a tagged template, `` ldapEscape.filter`(uid=${userInput})` `` - it was last published in June 2022, so check it is still an acceptable dependency. There is no package named `ldapjs-escape`: a `require()` of one throws at load and takes the whole route down
- Validate and sanitize all user inputs with strict allowlists before using in LDAP queries
- Escape LDAP special characters: `*`, `(`, `)`, `\` and NUL as a backslash followed by the
  two-digit hex code per RFC 4515 - `\2a`, `\28`, `\29`, `\5c`, `\00`. RFC 4515 assigns no meaning
  to `/`, so escaping it is unnecessary and corrupts legitimate values - and if escaping by sequential replacement, replace `\` first so the inserted sequences are not escaped again
- Implement least-privilege access controls on LDAP directory operations
- Use framework-provided LDAP query builders instead of string concatenation

## Taint Sinks

`client.search()` (ldapjs) with a concatenated filter string

## Remediation Steps

- Identify all LDAP query construction points that use user input
- Replace string concatenation with a filter object (`EqualityFilter` and friends) passed to `client.search()`, or with `ldap-escape` where the filter has to remain a string
- Apply LDAP escaping functions to all user-supplied values
- Implement input validation with allowlists for username/search patterns
- Add logging and monitoring for suspicious LDAP query patterns
- Conduct security testing with LDAP injection payloads
