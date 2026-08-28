# CWE-91: XML Injection (aka Blind XPath Injection)

## LLM Guidance

XML Injection occurs when untrusted user input is incorporated into XML documents without proper validation or escaping, allowing attackers to modify XML structure or content. The core fix is to never construct XML through string concatenation; instead, use XML libraries that automatically escape user input as data. MITRE's name also covers XPath/XQuery injection, where the fix is closer to SQL parameterization - bind the value as an XPath variable rather than concatenating it. This is **not** the CWE for XML External Entity processing: a finding about `DOCTYPE`, external entities, or entity expansion is CWE-611, and hardening a parser does nothing for a document built by concatenation.

## Key Principles

- Never concatenate untrusted input directly into XML strings
- Use XML libraries with built-in escaping and serialization
- Treat all user input as data, not XML structure
- Validate and sanitize input before XML processing
- Implement allowlist validation for XML element/attribute names - builder APIs generally escape values passed to a text or attribute-value method but not names, so an element name built from input reintroduces structural injection through a different call
- Standard XML escaping does not make a value CDATA-safe: the five entity escapes do not cover the literal sequence `]]>`, which terminates the section early
- There is nothing to escape an XPath string literal *to* - XPath 1.0 literals cannot contain their own delimiter and define no escape sequence, so switching quote styles only moves the problem and stripping quotes corrupts legitimate data. Bind a variable, or select a static node set and compare in application code

## Remediation Steps

- Trace the data flow - Identify where untrusted data enters (source) and where XML is constructed (sink)
- Replace string concatenation - Use safe XML APIs (e.g., `DocumentBuilder`, `XMLStreamWriter`, `lxml.etree`) that treat input as data
- Escape special characters - If concatenation is unavoidable, escape `<`, `>`, `&`, `"`, `'` using library functions
- Validate input format - Apply strict allowlist validation on data that determines XML structure
- Use parameterized APIs - build XML with DOM methods like `createElement()` and `createTextNode()` instead of string concatenation
- Test edge cases - Verify fix with malicious payloads containing XML metacharacters
