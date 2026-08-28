# CWE-91: XML Injection (aka Blind XPath Injection) - Java

## LLM Guidance

XML Injection in Java occurs when untrusted user input is used to construct XML documents without proper validation or escaping. Attackers inject special characters (`<`, `>`, `&`, `'`, `"`) to manipulate XML structure, potentially causing data corruption, authentication bypass, or information disclosure.

**Primary Defence:** Use DOM API methods (`DocumentBuilder`, `Element.setAttribute()`, `Element.setTextContent()`) or sanitize input by escaping XML metacharacters.

## Key Principles

- Never concatenate untrusted input directly into XML strings
- Use DOM APIs (`createElement`, `setTextContent`, `setAttribute`) which auto-escape content
- Validate and sanitize all user input before XML processing
- Use XML libraries that enforce proper encoding (JAXB, DOM4J with safe configurations)
- Disable external entity processing to prevent XXE attacks
- Use `XMLStreamWriter.writeCharacters()`/`writeAttribute()`, which escape the value; an element or attribute *name* built from input bypasses that entirely, since names are not escaped
- For XPath, compile the expression once (`javax.xml.xpath.XPathExpression`) with a variable resolver and bind the value - concatenating it is the same shape as SQL injection and, unlike SQL, XPath 1.0 literals have no escape sequence for their delimiter
- `escapeXml11()` (Commons Text) escapes text content; it does not make a value safe inside a CDATA section, where the sequence `]]>` still terminates early
- A `Transformer` writing the result applies its own escaping - do not pre-escape the values you hand it, or the output is double-encoded

## Taint Sinks

String-concatenated XML via `+`/`String.format()`, `StringBuilder.append()` building XML tags

## Remediation Steps

- Replace string concatenation with DOM API methods for XML construction
- Apply current XML escaping (`escapeXml10`/`escapeXml11`) only when string-based construction is unavoidable
- Validate input against whitelist patterns before XML processing
- Configure parsers to explicitly disable DOCTYPE declarations, external entities, and external schema/DTD access
- Use parameterized XPath queries instead of string concatenation
