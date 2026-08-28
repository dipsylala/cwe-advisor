# CWE-91: XML Injection (aka Blind XPath Injection) - JavaScript

## LLM Guidance

XML Injection in JavaScript/Node.js applications occurs when untrusted user input is used to construct XML documents without proper validation or escaping. Attackers can manipulate XML structure by injecting special characters like `<`, `>`, `&`, `'`, and `"`, leading to data corruption, authentication bypass, or information disclosure.

**Primary Defence:** Use XML builder libraries like `xmlbuilder2` or `fast-xml-parser` that automatically escape user input, or manually escape special XML characters before insertion.

## Key Principles

- Always use XML builder libraries with automatic escaping instead of string concatenation
- Validate and sanitize all user input before incorporating into XML documents
- Escape XML special characters: `&` → `&amp;`, `<` → `&lt;`, `>` → `&gt;`, `'` → `&apos;`, `"` → `&quot;`
- Use parameterized XML APIs or templating that separates data from structure
- Implement input validation with allowlists for expected formats

## Taint Sinks

Template literals/string concatenation building XML, `+` into raw XML strings

## Remediation Steps

- Replace string concatenation XML building with library-based approaches
- Install and use `xmlbuilder2` or similar library with built-in escaping, building nodes with `create()`/`.ele()` and setting values with `.txt()`, which escapes
- Apply XML escaping function to all user-controlled data before insertion
- Validate input against strict schemas or patterns before processing
- Enable XML parser security features (disable external entities, limit depth)
- Test with malicious payloads containing `<`, `>`, `&`, `CDATA` sections
