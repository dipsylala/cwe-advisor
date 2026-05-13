# CWE-90: LDAP Injection - Python

## LLM Guidance

LDAP Injection occurs when untrusted user input is concatenated into LDAP queries without proper sanitization, allowing attackers to manipulate queries to bypass authentication, escalate privileges, or extract sensitive directory data.

**Primary Defence:** Use `ldap3` filter escaping with strict allowlists for user-controlled filter values and DN components. LDAP filters are not SQL-style prepared statements, so never concatenate raw user input into filter strings.

## Key Principles

- Use `ldap3` with escaped filter values instead of raw string concatenation
- Escape all special LDAP characters in user input using `ldap3.utils.conv.escape_filter_chars()`
- Apply allowlist validation on user input before query construction
- Implement least-privilege access for LDAP service accounts
- Use DN (Distinguished Name) sanitization for attribute values

## Remediation Steps

- Replace string concatenation with escaped filter construction
- Apply `escape_filter_chars()` to all user-controlled variables in LDAP filters
- Validate input against expected patterns (e.g., alphanumeric usernames)
- Review LDAP query logging to detect injection attempts
- Test filters with malicious payloads like `*)(objectClass=*)` and `admin)(&(password=*)`
- Restrict LDAP bind account permissions to minimum required scope

## Safe Pattern

```python
import os
from ldap3 import Server, Connection, ALL, Tls
from ldap3.utils.conv import escape_filter_chars

server = Server('ldaps://ldap.example.com', use_ssl=True, get_info=ALL)
conn = Connection(
    server,
    user=os.environ['LDAP_BIND_DN'],
    password=os.environ['LDAP_BIND_PASSWORD']
)

# Safe: escape user input
username = escape_filter_chars(user_input)
search_filter = f"(&(objectClass=person)(uid={username}))"

conn.search('dc=example,dc=com', search_filter)
```
