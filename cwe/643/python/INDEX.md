# CWE-643: XPath Injection - Python

## LLM Guidance

The sink is an XPath string built with an f-string, `%`, or `.format()` and passed to `lxml`'s
`xpath()` or `etree.XPath()`, or to `xml.etree.ElementTree`'s `find`/`findall`. Python has the best
answer of the common languages: `lxml` supports XPath variables natively, so
`tree.xpath("//user[@name=$name]", name=value)` binds the value with no expression rewriting and no
extra type. Prefer that. The standard library's `ElementTree` implements only a limited XPath subset
and offers no variable binding at all, so a finding there is usually a reason to move to `lxml`.

## Key Principles

- Bind with `lxml`: pass the value as a keyword argument to `tree.xpath()` or call a compiled
  `etree.XPath("//user[@name=$name]")` with `name=value`. Compiling once and calling with different
  values is both the safe form and the fast one
- The `$name` reference must be the whole operand. Interpolating into a quoted literal and *also*
  passing a variable, or writing `'$name'` inside quotes, produces a literal dollar sign rather than a
  binding and silently leaves the injection in place
- `xml.etree.ElementTree` supports a restricted XPath subset with no variables, so there is nothing to
  bind to. Either move the query to `lxml`, or select a static node set with `findall` and compare the
  value in Python
- Do not build a quote-escaping helper. XPath 1.0 string literals define no escape sequence, so a
  `replace("'", "''")` borrowed from SQL habits does not neutralise anything, and stripping quotes
  corrupts a legitimate value such as `O'Brien`
- Only values bind. An element or attribute name taken from input stays structural, so allowlist it
  and use the matched constant - a dict lookup returning the canonical name is the usual shape
- A non-empty result list means the predicate matched, not that the credentials were right. For an
  authentication query read the matched element's fields and compare them in Python, and reject a
  result list longer than one rather than taking `[0]`
- `lxml`'s parser resolves external entities by default in some configurations, and XPath binding does
  nothing about that. Parse attacker-reachable XML with
  `etree.XMLParser(resolve_entities=False, no_network=True)`, or use `defusedxml`, and treat the
  entity question as the separate finding it is (CWE-611)

## Taint Sinks

`lxml.etree._Element.xpath()`, `lxml.etree.XPath()`, `lxml.etree.ETXPath()`,
`xml.etree.ElementTree.Element.find()`/`findall()`/`findtext()`, `xml.dom.minidom` traversal built
from a formatted string

## Remediation Steps

- Locate - find `xpath(`, `etree.XPath(`, `find(`, or `findall(` whose argument is an f-string, a `%`
  format, or a `.format()` call
- Trace data flow - follow the value from `request.args`, `request.form`, a JSON body, or a header to
  the expression, and confirm it lands inside a quoted literal in a predicate
- Identify the unsafe pattern - interpolation into the expression, a quote-stripping helper, or an
  `ElementTree` query that cannot be parameterised at all
- Replace the unsafe pattern - rewrite the expression with `$name` references and pass the values as
  keyword arguments to `xpath()`, or compile once with `etree.XPath()` and call it with the values
- Bind, encode, validate, or authorize - allowlist any structural fragment through a dict of permitted
  names and use the looked-up value; for an authentication query compare the matched element's fields
  explicitly rather than testing the result list for truthiness
- Harden configuration - parse with `resolve_entities=False` and `no_network=True`, or use
  `defusedxml`, where the document is attacker-reachable
- Test - submit `' or '1'='1`, `") or ("1"="1`, and a legitimate value containing an apostrophe, and
  confirm the first two return an empty result while the third still matches
