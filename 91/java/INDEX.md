# CWE-91: XML Injection - Java

## LLM Guidance

XML Injection in Java occurs when untrusted user input is used to construct XML documents without proper validation or escaping. Attackers inject special characters (`<`, `>`, `&`, `'`, `"`) to manipulate XML structure, potentially causing data corruption, authentication bypass, or information disclosure.

**Primary Defence:** Use DOM API methods (`DocumentBuilder`, `Element.setAttribute()`, `Element.setTextContent()`) or sanitize input by escaping XML metacharacters.

## Key Principles

- Never concatenate untrusted input directly into XML strings
- Use DOM APIs (`createElement`, `setTextContent`, `setAttribute`) which auto-escape content
- Validate and sanitize all user input before XML processing
- Use XML libraries that enforce proper encoding (JAXB, DOM4J with safe configurations)
- Disable external entity processing to prevent XXE attacks

## Remediation Steps

- Replace string concatenation with DOM API methods for XML construction
- Apply current XML escaping (`escapeXml10`/`escapeXml11`) only when string-based construction is unavoidable
- Validate input against whitelist patterns before XML processing
- Configure parsers to explicitly disable DOCTYPE declarations, external entities, and external schema/DTD access
- Use parameterized XPath queries instead of string concatenation

## Safe Pattern

```java
import org.w3c.dom.*;
import javax.xml.parsers.*;

// Safe: Using DOM API (auto-escapes)
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
DocumentBuilder builder = factory.newDocumentBuilder();
Document doc = builder.newDocument();

Element root = doc.createElement("user");
Element name = doc.createElement("name");
name.setTextContent(userInput); // Auto-escaped, safe
root.appendChild(name);

// Alternative: Explicit escaping for string-based XML
String safe = StringEscapeUtils.escapeXml11(userInput);
String xml = "<user><name>" + safe + "</name></user>";
```
