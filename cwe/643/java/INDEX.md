# CWE-643: XPath Injection - Java

## LLM Guidance

In Java the sink is `javax.xml.xpath.XPath.evaluate()` or a compiled `XPathExpression.evaluate()`
whose expression string was built by concatenation, typically against a user store held in XML. The
fix is `XPath.setXPathVariableResolver()`: reference the value as `$name` in an otherwise static
expression and return it from the resolver, so the parser treats it as a value and never as
expression syntax. There is no escaping alternative - an XPath 1.0 literal has no escape sequence -
so a hand-written quote filter is not a substitute.

## Key Principles

- Compile a static expression containing `$username`-style references and install an
  `XPathVariableResolver` with `setXPathVariableResolver()` before `compile()` or `evaluate()`. The
  resolver's `resolveVariable(QName)` returns the value as an `Object`, usually a `String`
- Set the resolver on the `XPath` instance *before* compiling: an expression compiled without one
  throws `XPathExpressionException` when it reaches an unresolvable variable, which is a failure to
  fix rather than a fix that fails safe
- `XPathFactory` and `XPath` are not thread-safe, and a variable resolver holding per-request state on
  a shared instance leaks values between requests. Create the `XPath` per use, or make the resolver
  stateless and pass values through a fresh instance
- Do not reach for `StringEscapeUtils` or a hand-rolled quote-doubler. Apache Commons Text has no
  XPath escaper because there is nothing correct to escape to, and a filter that strips quotes breaks
  legitimate names such as `O'Brien`
- Where the expression must vary structurally - a element or attribute name chosen by the caller -
  bind what you can and allowlist the rest, using the matched constant rather than the request value
- `javax.xml.xpath` implements XPath 1.0. Saxon and other XPath 2.0/3.1 engines have their own
  variable-binding API (`XPathSelector.setVariable`), so confirm which engine is actually on the
  classpath before proposing an API
- An authentication query is the common shape here: `//user[name/text()='X' and pass/text()='Y']`
  returns a node set, and a value making the predicate universally true returns every user, so branch
  on the specific node matched rather than on the node set being non-empty
- Parse the document with a hardened parser as well - the same code path usually reads attacker-
  reachable XML, and XPath binding does nothing about external entities (CWE-611)

## Taint Sinks

`XPath.evaluate()`, `XPath.compile()`, `XPathExpression.evaluate()`, `XPathFactory.newXPath()` results
used with a concatenated string, `javax.xml.xpath.XPathExpression` built by `String.format` or `+`

## Remediation Steps

- Locate - find `XPath.evaluate` or `XPath.compile` calls whose argument is built with `+`,
  `String.format`, `StringBuilder`, or a text block interpolation
- Trace data flow - follow the value from `request.getParameter`, a deserialized field, or a header to
  the expression string, and note whether it lands inside a quoted literal
- Identify the unsafe pattern - concatenation into the expression, or an existing "sanitizer" that
  strips or doubles quotes and is therefore both unsafe and lossy
- Replace the unsafe pattern - rewrite the expression as a static string using `$variable` references,
  implement `XPathVariableResolver` to return the values by `QName`, and call
  `setXPathVariableResolver` on the `XPath` before compiling
- Bind, encode, validate, or authorize - allowlist any structural fragment that must remain dynamic,
  and for an authentication query compare the resolved node's fields explicitly rather than testing
  whether the node set is empty
- Harden configuration - disable external entity resolution on the `DocumentBuilderFactory` that
  produced the document, and create the `XPath` per request rather than sharing a stateful resolver
- Test - submit `' or '1'='1`, `") or ("1"="1`, and a legitimate value containing an apostrophe, and
  confirm the first two match nothing while the third still works
