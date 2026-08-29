# CWE-91: XML Injection (aka Blind XPath Injection) - Java

## LLM Guidance

XML Injection in Java occurs when untrusted user input is used to construct XML documents without proper validation or escaping. Attackers inject special characters (`<`, `>`, `&`, `'`, `"`) to manipulate XML structure, potentially causing data corruption, authentication bypass, or information disclosure.

**Primary Defence:** Build the document through the DOM or a stream writer (`Document.createElement`, `Element.setTextContent()`, `Element.setAttribute()`, `XMLStreamWriter`) so the serializer escapes the values, rather than assembling markup as a string.

## Key Principles

- Never concatenate untrusted input directly into XML strings
- The DOM setters do not escape - they store the string verbatim, and `setAttribute`'s javadoc says the value "needs to be appropriately escaped by the implementation when it is written out". The protection therefore lives in the serialization step, so a hand-rolled writer over a correctly built tree still injects
- Names are the gap in that protection. `XMLStreamWriter` promises escaping only for "character content and attribute values" and explicitly does no well-formedness checking, so an element or attribute name built from input passes through raw. The DOM is stricter: `createElement`/`setAttribute` throw `INVALID_CHARACTER_ERR` for a name that is not an XML name - which is a crash rather than a defence, so allowlist the name first
- Know the documented escape set, because it is smaller than the five metacharacters: `XMLStreamWriter.writeCharacters()` covers `&`, `<`, `>`, and `writeAttribute()` adds `"`. The apostrophe is in neither
- `writeCData` documents no escaping and no validation at all, and `]]>` inside it terminates the section early. `escapeXml10`/`escapeXml11` do not help there either - the five entities do not cover the sequence
- Use `org.apache.commons.text.StringEscapeUtils` for `escapeXml10`/`escapeXml11`; the identically named `org.apache.commons.lang3` class has been deprecated in favour of it since Commons Lang 3.6. Note that `escapeXml10` silently *deletes* characters outside the XML 1.0 range rather than escaping them, so it can alter data as well as protect it. Do not substitute `escapeHtml4()` because it is already imported - it emits named entities beyond XML's five, which a strict parser with no DOCTYPE rejects
- For XPath, compile the expression with a variable resolver and bind the value - concatenating it is the same shape as SQL injection and, unlike SQL, XPath 1.0 literals have no escape sequence for their delimiter. The resolver has to be in place at `compile()` time, since a compiled `XPathExpression` captures the one then in effect; see CWE-643
- A `Transformer` writing the result applies its own escaping - do not pre-escape the values you hand it, or the output is double-encoded
- Prefer DOM4J's `XMLWriter`, whose text escaping is on by default and toggled off only by `setEscapeText(false)`, over JAXB for this: JAXB was removed from the JDK in 11 (JEP 320), needs the `jakarta.xml.bind` dependency, and its specification documents no character-escaping contract
- A `DOCTYPE`, external-entity or entity-expansion finding is CWE-611, not this one, and hardening the parser does nothing for a document built by concatenation

## Taint Sinks

String-concatenated XML via `+`/`String.format()`, `StringBuilder.append()` building XML tags, `XMLStreamWriter.writeCData()`

## Remediation Steps

- Replace string concatenation with DOM or `XMLStreamWriter` construction, and serialize through the library rather than a hand-rolled writer
- Apply current XML escaping (`escapeXml10`/`escapeXml11` from Commons Text) only when string-based construction is unavoidable
- Allowlist any element or attribute name taken from input, separately from the value escaping
- Use parameterized XPath queries instead of string concatenation, installing the resolver before `compile()`
- Test with the metacharacters and with `]]>` where a CDATA section is written; confirm a name built from input is rejected rather than emitted
