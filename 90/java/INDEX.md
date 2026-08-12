# CWE-90: Improper Neutralization of Special Elements used in an LDAP Query ('LDAP Injection') - Java

## LLM Guidance

LDAP Injection occurs when untrusted data is used to construct LDAP search filters or DN strings without proper encoding, allowing attackers to manipulate directory searches and access unauthorized data.

**Primary Defence:** For search filters, use JNDI's own parameterized `DirContext.search()` overload, which takes filter arguments separately and escapes them automatically - no extra dependency required. DN construction has no parameterized JNDI API, so encode with OWASP ESAPI's `encodeForDN()` or build DNs with Spring LDAP's `LdapNameBuilder` instead.

## Key Principles

- Prefer JNDI's parameterized search filter overload over building filter strings by concatenation - the JDK escapes each argument for you
- DNs have no parameterized construction API - encode user input with ESAPI's `encodeForDN()` or assemble DNs with Spring LDAP's `LdapNameBuilder`
- Use Spring LDAP's `LdapQueryBuilder` instead of raw JNDI when the framework is already a dependency - it applies safe encoding automatically
- Validate input against allowlists for expected characters and patterns
- Apply principle of least privilege to LDAP service accounts

## Taint Sinks

`DirContext.search()` with a concatenated filter string, string-concatenated DN construction, `InitialDirContext` lookups built from concatenated names

## Remediation Steps

- Locate concatenated filter or DN strings feeding `DirContext.search()`, `InitialDirContext`, or similar JNDI calls
- For search filters - replace concatenation with `{0}`-style placeholders and pass user input via the `filterArgs` parameter of `DirContext.search()`
- For DN construction - encode user input with `ESAPI.encoder().encodeForDN(input)` before assembling the DN, or build it with Spring LDAP's `LdapNameBuilder`
- Alternatively, migrate to Spring LDAP's `LdapQueryBuilder` for automatic protection on both filters and DNs
- Add input validation to reject unexpected characters before encoding
- Test with payloads like `*)(uid=*))(|(uid=*` to verify protection

## Safe Pattern

```java
// SAFE: JNDI parameterized filter - filterArgs are escaped automatically
String filter = "(uid={0})";
NamingEnumeration<SearchResult> results = ctx.search(
        "ou=users,dc=example,dc=com", filter, new Object[]{username}, searchControls);

// SAFE: ESAPI encoding for DN construction - no parameterized API exists for DNs
import org.owasp.esapi.ESAPI;
String safeName = ESAPI.encoder().encodeForDN(username);
String dn = "uid=" + safeName + ",ou=users,dc=example,dc=com";
```
