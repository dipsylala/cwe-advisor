# CWE-91: XML Injection (aka Blind XPath Injection) - C#

## LLM Guidance

XML Injection occurs when untrusted user input is embedded into XML documents without proper validation or escaping, allowing attackers to manipulate XML structure using special characters (`<`, `>`, `&`, `'`, `"`). This can lead to data corruption, authentication bypass, or information disclosure. Use LINQ to XML APIs (`XElement`, `XAttribute`) or `XmlWriter` methods instead of string concatenation; escape manually only when string construction is unavoidable.

## Key Principles

- Never concatenate user input directly into XML strings
- Use LINQ to XML constructors that automatically escape content
- Apply `SecurityElement.Escape()` only when string manipulation is unavoidable
- Validate input against strict allowlists before XML construction
- Parse and reconstruct XML rather than modifying as strings
- Build XML with a writer or object model that escapes for you - `XmlWriter.WriteElementString()`, `XDocument`/`XElement` - rather than concatenating markup; the writer escapes *values*, so an element or attribute *name* taken from input is still structural injection
- `XmlSerializer` on a type you control emits a well-formed document; the risk is a caller-supplied type name deciding what gets constructed, which is CWE-502
- For XPath, bind through an `XsltContext`/`XsltArgumentList` variable rather than concatenating the value into the expression - XPath string literals have no escape for their own delimiter
- Set the declaration explicitly (`XDeclaration`) so the encoding the document claims matches the bytes actually written

## Taint Sinks

String-concatenated/interpolated XML (`$"<tag>{input}</tag>"`), `XmlWriter.WriteRaw()`

## Remediation Steps

- Replace string concatenation with `XElement`/`XAttribute` constructors
- Use `XmlWriter.WriteString()` / `WriteAttributeString()` directly; only wrap untrusted data with `SecurityElement.Escape()` for unavoidable string-based methods
- Implement input validation using allowlists for expected characters/patterns
- Use parameterized XML construction methods consistently
- Test with XML metacharacters (`<test>`, `&payload;`, `"value"`) to verify escaping
- Review existing code for `.ToString()` concatenation patterns
