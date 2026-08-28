# CWE-643: Improper Neutralization of Data within XPath Expressions (XPath Injection)

## LLM Guidance

XPath injection occurs when untrusted input is concatenated into an XPath expression, letting an
attacker change which nodes the expression selects rather than only what it matches. The classic
result is an authentication bypass, where a value closing the quoted literal and adding `or '1'='1'`
turns a single-user lookup into the whole document. The fix parallels SQL parameterization - bind the
value as an XPath variable - but with one difference that decides the whole remediation: **XPath 1.0
string literals have no escape sequence**, so escaping is not available as a fallback. A finding about
building an XML *document* by concatenation is CWE-91, and one about `DOCTYPE` or external entities is
CWE-611.

## Key Principles

- Bind the value as an XPath variable and leave the expression itself static. This is the only fix
  that generalises; everything else is a workaround for an API that cannot do it
- Do not attempt to escape the value into the literal. An XPath 1.0 string literal cannot contain its
  own delimiter and defines no escape sequence, so quote-doubling does not work as it does in SQL,
  switching delimiter moves the problem to the other quote character, and stripping quotes silently
  corrupts legitimate data such as a name containing an apostrophe
- Where the language or library offers no variable binding, do not synthesise one. Select a static
  node set with no untrusted input in the expression and compare the value in application code, which
  is slower and completely safe
- Only values can be bound. An element name, attribute name, axis, or predicate operator taken from
  input remains structural injection, so validate those against an allowlist and use the matched
  canonical value rather than the input
- Treat an XPath authentication query as the security decision it is: "a node was found" is not "the
  credentials matched", since a value making the predicate universally true returns every node
- Assume the attacker reads the document one boolean at a time. Blind XPath injection extracts
  structure from true/false differences in the response, so suppressing error messages narrows the
  channel without closing the hole - and an XML file holding credentials turns any injection into full
  disclosure, because XPath has no per-node access control

## Remediation Steps

- Locate - find where the XPath expression is built and where the untrusted value enters it, and
  confirm the value lands inside a string literal or a predicate rather than the document being parsed
- Identify the unsafe pattern - string concatenation or interpolation into the expression, or a
  hand-written escape or quote-stripping routine standing in for binding
- Replace the unsafe pattern - move the value to an XPath variable and reduce the expression to a
  static string, or select a static node set and compare in code where the library cannot bind
- Validate structural input separately - allowlist any element or attribute name that comes from
  input, and use the value selected from the allowlist rather than the original
- Test - submit values containing a single quote, a double quote, `or '1'='1`, and a predicate that
  always evaluates true, and confirm the query returns no match rather than every node
