# CWE-611: Improper Restriction of XML External Entity Reference - Java

## LLM Guidance

XXE vulnerabilities occur when XML parsers process external entity references in untrusted XML, allowing attackers to read files, perform SSRF attacks, or cause denial of service. Java's XML parsers (DocumentBuilder, SAXParser, XMLReader) are vulnerable by default and must be explicitly configured securely. The core fix is to disable DTDs and external entity processing entirely.

## Key Principles

- Disable DTDs completely using `FEATURE_SECURE_PROCESSING` and disallow DOCTYPE declarations
- Set all external entity features to `false` on parser factories
- Use secure parser configurations consistently across all XML processing code
- Consider using simpler data formats like JSON when XML features aren't required

## Taint Sinks

`DocumentBuilder.parse()`, `SAXParser.parse()`, `XMLReader.parse()`, `XMLInputFactory.createXMLStreamReader()`

## Remediation Steps

- Enable secure processing - `factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)`
- Disable DTDs - `factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`
- Disable external general entities - `factory.setFeature("http://xml.org/sax/features/external-general-entities", false)`
- Disable external parameter entities - `factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false)`
- Disable external DTDs - `factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false)`
- Disable XInclude and entity reference expansion - `factory.setXIncludeAware(false)` and `factory.setExpandEntityReferences(false)`
- Apply these settings to all DocumentBuilderFactory, SAXParserFactory, and XMLInputFactory instances
