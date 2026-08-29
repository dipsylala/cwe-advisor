# CWE-91: XML Injection (aka Blind XPath Injection) - C#

## LLM Guidance

XML Injection occurs when untrusted user input is embedded into XML documents without proper validation or escaping, allowing attackers to manipulate XML structure using special characters (`<`, `>`, `&`, `'`, `"`). This can lead to data corruption, authentication bypass, or information disclosure. Use LINQ to XML APIs (`XElement`, `XAttribute`) or `XmlWriter` methods instead of string concatenation; escape manually only when string construction is unavoidable.

## Key Principles

- Build XML with a writer or object model rather than concatenating markup - `XmlWriter.WriteElementString()`/`WriteString()`, or `XDocument`/`XElement`. The escaping happens when the tree is *serialized* by an `XmlWriter`, not in the `XElement` constructor, so a custom serialization path is where it can be lost
- What the writer escapes is *values*, so an element or attribute *name* taken from input is still structural injection through a different call. Allowlist names before they reach `WriteStartElement`/`XName`
- The escaped set differs by position: `WriteString` replaces `&`, `<` and `>`, and adds `"` and `'` only when it is writing inside an attribute value; `WriteAttributeString` documents quote replacement
- Apply `SecurityElement.Escape()` (all five characters) only when string manipulation is unavoidable; it is scoped by its own class documentation to the security object model rather than offered as a general XML escaper
- Escaping does not make a value CDATA-safe: none of the five entities covers the literal `]]>`, which terminates the section early
- `XmlWriter.WriteRaw()` is documented as not escaping anything - "You should not pass arbitrary data to this method"
- `XmlSerializer` on a type you control emits a well-formed document; the risk is a caller-supplied type name deciding what gets constructed, which is CWE-502
- **XPath is a different fix, not this one.** .NET has no built-in XPath variable binding: `XPathExpression.SetContext` resolves namespaces, and `XsltArgumentList` is consumed by `XslCompiledTransform.Transform`, not by `XPathExpression`. Binding requires deriving your own `XsltContext` with `ResolveVariable`. See CWE-643 for the full treatment
- The declared encoding is not authoritative on every save path: `XDeclaration` governs `Save(string)`/`Save(Stream)`, while `Save(TextWriter)` and an explicit `XmlWriter` take their encoding from the writer and rewrite the declaration to match. Set it on whichever of the two is actually in use

## Taint Sinks

String-concatenated/interpolated XML (`$"<tag>{input}</tag>"`), `XmlWriter.WriteRaw()`

## Remediation Steps

- Replace string concatenation with `XElement`/`XAttribute` constructors or `XmlWriter` methods
- Use `XmlWriter.WriteString()` / `WriteAttributeString()` directly; only wrap untrusted data with `SecurityElement.Escape()` for unavoidable string-based methods
- Allowlist any element or attribute name that comes from input, separately from the value escaping
- Route an XPath finding to CWE-643 rather than escaping the value into the expression
- Test with XML metacharacters (`<test>`, `&payload;`, `"value"`) and with `]]>` where a CDATA section is written, to verify escaping
- Check every interpolated slot, not the first one - an attribute value a few lines below the escaped element content is a separate call that needs its own escape, and a sibling overload still building `SelectNodes($"...{value}...")` leaves the sink open for the path nobody reviewed
- Review existing code for `.ToString()` concatenation patterns
