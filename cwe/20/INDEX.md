# CWE-20: Improper Input Validation

## LLM Guidance

Improper Input Validation occurs when applications fail to enforce constraints on externally supplied data before use. While validation alone doesn't prevent all vulnerabilities, its absence allows unexpected or malformed values to reach security-sensitive logic, enabling SQL injection, XSS, command injection, and other attacks. Static analysis flags CWE-20 when code accepts external input without clear type, range, format, or semantic constraints. MITRE marks CWE-20 Discouraged for mapping, so treat the finding as a pointer to the lower-level weakness that actually applies rather than as the finding itself.

## Key Principles

- CWE-20 is abstract - the correct fix depends on identifying the specific child CWE that matches how unvalidated input is actually used
- Where the value reaches an interpreter (SQL, HTML, shell, LDAP, XML, eval), validation is supplementary and the encoding or parameterization is the fix; where it is used as an array index, quantity, loop bound, state selector, or business amount there is nothing to parameterize and constraint checking *is* the fix
- Allowlist the accepted form rather than denylisting known-bad patterns: a denylist enumerates what someone thought of, so every encoding, case variant, or equivalent spelling omitted from it is accepted by default
- Anchor validation regexes to the whole string: `$` matches before a trailing newline in Python's `re`, .NET's `Regex` and PCRE, so `^[a-zA-Z0-9.-]+$` accepts `evil.com\n`. Use `re.fullmatch()`, `Matcher.matches()`, or `\A...\z`
- Address the specific security risk - remediation must target the vulnerability enabled by unconstrained input, not just add generic validation
- Trace data flow completely - follow input from entry point through all transformations to where it's consumed
- Defence-in-depth - combine input validation with context-specific output encoding, parameterized queries, and principle of least privilege

## Remediation Steps

- Identify input origin - HTTP parameter, header, file upload, API request, database result, or external system
- Trace to consumption point - determine where input is used - HTML output, SQL query, shell command, file path, LDAP query, XML parser, eval statement
- Classify the specific vulnerability - map the sink to its child CWE and load that entry as the primary guidance: SQL query CWE-89, HTML output CWE-79, file path CWE-22, shell command CWE-78, dynamic evaluation CWE-94, redirect target CWE-601, outbound URL CWE-918, deserialization CWE-502, log message CWE-117, array index CWE-129, arithmetic on a size CWE-190, configuration value CWE-15
- Apply the child CWE's defence - that entry carries the concrete fix; CWE-20 contributes the constraint and canonicalization rules below, not a substitute for it
- Enforce input constraints - validate type, length, format, character set, and business logic rules at entry points
- Validate the value in the form the sink will see - decode and canonicalize before checking, and account for what the framework already decoded (`request.getParameter`, `@RequestParam`, ASP.NET model binding and `request.args` all return URL-decoded values, so a rule matching `%2e%2e` never fires while the decoded `../` passes)
- Reject invalid input - fail securely by rejecting malformed data rather than attempting sanitization
- Test both directions - malicious payloads for the specific child CWE, and legitimate awkward values (unicode names, apostrophes, maximum permitted length, numeric range boundaries); a rule that rejects everything passes every attack test and only the accept-side assertions catch it
