# CWE-611: Improper Restriction of XML External Entity Reference - Java

## LLM Guidance

XXE vulnerabilities occur when XML parsers process external entity references in untrusted XML, allowing attackers to read files, perform SSRF attacks, or cause denial of service. Java's XML parsers (DocumentBuilder, SAXParser, XMLReader) are vulnerable by default and must be explicitly configured securely. The core fix is to disable DTDs and external entity processing entirely.

## Key Principles

- Disallow DOCTYPE declarations outright with the `disallow-doctype-decl` feature - that, not
  `FEATURE_SECURE_PROCESSING`, is what stops a DTD. The Javadoc scopes secure processing to
  "implementation limits" such as entity expansion, which is denial of service rather than entity
  resolution; it is worth setting, but not as the control that closes this finding
- Set all external entity features to `false` on parser factories
- Use secure parser configurations consistently across all XML processing code
- Consider using simpler data formats like JSON when XML features aren't required

## Taint Sinks

`DocumentBuilder.parse()`, `SAXParser.parse()`, `XMLReader.parse()`, `XMLInputFactory.createXMLStreamReader()`

## Remediation Steps

- Enable secure processing - `factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)` - and
  set `javax.xml.accessExternalDTD` and `javax.xml.accessExternalSchema` to the empty string, which
  are the properties that actually restrict external access. Both arrived with JAXP 1.5 in 7u40 and
  JDK 8; on 7u40 setting secure processing does not change them, while on JDK 8 and later it does
- Disable DTDs - `factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`
- Disable external general entities - `factory.setFeature("http://xml.org/sax/features/external-general-entities", false)`
- Disable external parameter entities - `factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false)`
- Disable external DTDs - `factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false)`
- Disable XInclude with `factory.setXIncludeAware(false)`. `setExpandEntityReferences(false)` is worth
  setting but is documented only as controlling whether DOM expands entity reference nodes, not as an
  XXE control - do not treat either as the primary defence in place of `disallow-doctype-decl`
- Apply these settings to every `DocumentBuilderFactory` and `SAXParserFactory`, and wrap each
  `setFeature` call: a parser that does not recognise a feature URI throws
  `ParserConfigurationException` (or `SAXNotRecognizedException`), and a fix that throws is not a fix
- `XMLInputFactory` takes none of those feature URIs - it is configured with properties instead.
  Set `XMLInputFactory.SUPPORT_DTD` to false, which otherwise defaults to true, and
  `IS_SUPPORTING_EXTERNAL_ENTITIES` to false. Applying the `setFeature` list to a StAX factory throws
  rather than hardening it
