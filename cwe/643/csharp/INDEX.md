# CWE-643: XPath Injection - C#

## LLM Guidance

The sinks are `XmlNode.SelectSingleNode()`/`SelectNodes()`, `XPathNavigator.Select()`/`Evaluate()`,
and `XPathExpression.Compile()` given a string built by concatenation or interpolation. .NET differs
from Java and Python in a way that decides the fix: **there is no built-in XPath variable binding**.
`XPathExpression.SetContext` takes an `IXmlNamespaceResolver` or `XmlNamespaceManager` and resolves
*namespaces*, not variables. Binding requires a custom `XsltContext` supplying `IXsltContextVariable`
implementations, so for most findings the better remediation is to select a static node set and
compare the value in C#, or to move the query to LINQ to XML.

## Key Principles

- Do not assume `SetContext` parameterises the expression. It handles namespace prefixes only, and an
  expression passed to it with an interpolated value is exactly as injectable as before
- Where a static expression is possible, select the candidate node set with no untrusted input in the
  expression and compare the value with `string.Equals(..., StringComparison.Ordinal)` in C#. This is
  the fix that fits most findings and needs no extra type
- Use LINQ to XML for new code: `XDocument`/`XElement` with a `Where` predicate keeps the untrusted
  value in C# where the compiler treats it as data, and never builds an expression string at all
- Reserve the custom `XsltContext` route for expressions that genuinely must stay dynamic and
  performance-critical: derive from `XsltContext`, implement `ResolveVariable` returning an
  `IXsltContextVariable`, and pass it to `SetContext`, which accepts an `XsltContext` because it is
  also an `IXmlNamespaceResolver`
- Do not escape into the literal. XPath 1.0 defines no escape sequence inside a string literal, so
  doubling or replacing quotes is not the C# equivalent of a parameterised query and breaks a
  legitimate value containing an apostrophe
- Allowlist any structural fragment - element name, attribute name, axis - and use the matched
  constant, since only values could ever be bound even where binding exists
- `XmlDocument.SelectSingleNode` returning non-null means a node matched the predicate, not that the
  credentials were correct; for an authentication query, read the matched node's fields and compare
  them explicitly
- `XmlDocument` has its own `XmlResolver` property and needs it set to `null` where the XML is
  attacker-reachable. `XPathDocument` has no `XmlResolver` property to set - it takes the mitigation
  one level removed, by being constructed from an `XmlReader` that was itself created with an
  `XmlReaderSettings` carrying `XmlResolver = null` or `DtdProcessing.Prohibit`. Either way, XPath
  binding does nothing about external entities (CWE-611)

## Taint Sinks

`XmlNode.SelectSingleNode()`, `XmlNode.SelectNodes()`, `XPathNavigator.Select()`,
`XPathNavigator.Evaluate()`, `XPathNavigator.SelectSingleNode()`, `XPathExpression.Compile()`,
`XmlDocument.SelectNodes()` with an interpolated or concatenated string

## Remediation Steps

- Locate - find `SelectSingleNode`, `SelectNodes`, `Select`, `Evaluate`, or `XPathExpression.Compile`
  whose argument uses `$"..."` interpolation, `string.Format`, `+`, or a `StringBuilder`
- Trace data flow - follow the value from the request, a model binding, or a config read to the
  expression string, and confirm it lands inside a quoted literal in a predicate
- Identify the unsafe pattern - interpolation into the expression, or an assumption that `SetContext`
  or a quote-replacing helper already parameterises it
- Replace the unsafe pattern - make the expression static and move the comparison into C# with an
  ordinal string comparison, or rewrite the query with LINQ to XML; use a custom `XsltContext` with
  `IXsltContextVariable` only where the expression must stay dynamic
- Bind, encode, validate, or authorize - allowlist any structural fragment and use the matched
  constant, and for an authentication query compare the matched node's fields rather than testing for
  a non-null result
- Harden configuration - set `XmlResolver = null` or prohibit DTD processing on the reader that loads
  the document
- Test - submit `' or '1'='1`, `") or ("1"="1`, and a legitimate value containing an apostrophe, and
  confirm the first two select nothing while the third still resolves
