# CWE-611: Improper Restriction of XML External Entity Reference - PHP

## LLM Guidance

PHP's XML parsers can process external entities by default, leading to file disclosure, SSRF attacks, and denial of service. Proper configuration is essential to prevent XXE vulnerabilities.

**Primary Defence:** Call `libxml_disable_entity_loader(true)` before parsing XML (PHP < 8.0), omit `LIBXML_NOENT`, avoid `LIBXML_DTDLOAD` for untrusted XML, and use `LIBXML_NONET` as defense in depth.

## Key Principles

- Disable external entity loading globally before any XML parsing operations
- Omit parser flags that expand entities or load DTDs
- Validate and sanitize XML input to reject documents containing entity declarations
- Prefer JSON over XML when possible to eliminate XXE risk entirely
- Keep PHP updated (8.0+ has safer defaults with entity loader disabled by default)
- On PHP 8.4+ pass `LIBXML_NO_XXE` to the loader, which disables entity substitution regardless of other flags; `libxml_disable_entity_loader()` is deprecated in 8.0 and removed in 8.4, so code relying on it is not protected on a current runtime
- Never pass `LIBXML_NOENT` - the name reads like "no entities" and it does the opposite, enabling entity substitution
- Reject the document outright when `DOMDocument::$doctype` is non-null where a DTD has no legitimate use, which is stronger than disabling entity resolution
- `SoapClient` parses responses with the same libxml stack, so a malicious or compromised endpoint reaches it - override `__doRequest()` to parse hardened, and treat a `SoapFault` as a rejection

## Taint Sinks

`simplexml_load_string()`, `DOMDocument::loadXML()`, `XMLReader::XML()`, `xml_parse()`

## Remediation Steps

- Call `libxml_disable_entity_loader(true)` at application initialization for PHP < 8.0
- Remove `LIBXML_NOENT` flag from all `simplexml_load_*`, `DOMDocument::load*`, and `XMLReader` calls
- Explicitly pass `LIBXML_NONET` to prevent network access during parsing
- Never use `LIBXML_DTDLOAD` unless absolutely required with trusted input only
- Test with payloads containing `<!ENTITY>` declarations to verify protection
- Review all usages of `simplexml_*`, `DOMDocument`, `XMLReader`, and `xml_parse` functions
