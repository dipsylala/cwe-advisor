# CWE-611: Improper Restriction of XML External Entity Reference - PHP

## LLM Guidance

Since libxml 2.9.0 entity substitution is off by default, so on a modern build the finding is usually one of three things: code that passes `LIBXML_NOENT` (which enables substitution despite its name), a parser reached through a wrapper that sets it, or an older libxml. Establish which before changing anything, and note the remaining exposure is file disclosure and SSRF where substitution is on.

**Primary Defence:** Call `libxml_disable_entity_loader(true)` before parsing XML (PHP < 8.0), omit `LIBXML_NOENT`, avoid `LIBXML_DTDLOAD` for untrusted XML, and use `LIBXML_NONET` as defense in depth.

## Key Principles

- Disable external entity loading globally before any XML parsing operations
- Omit parser flags that expand entities or load DTDs
- Validate and sanitize XML input to reject documents containing entity declarations
- Prefer JSON over XML when possible to eliminate XXE risk entirely
- Attribute the safe default correctly: it comes from libxml 2.9.0 (2012), which disabled entity substitution, not from any PHP release - php.net's only PHP 8.0.0 note on `libxml_disable_entity_loader()` is its deprecation. The default also holds only while none of `LIBXML_NOENT`, `LIBXML_DTDVALID` or `LIBXML_DTDLOAD` is passed
- On PHP 8.4+ with libxml 2.13+, pass `LIBXML_NO_XXE` to the loader: it blocks external entity loading even where `LIBXML_NOENT` has turned entity substitution on, which is the combination that otherwise reopens XXE
- `libxml_disable_entity_loader()` was deprecated in 8.0 and still exists - it was not removed - but on 8.0+ it has nothing left to do, because libxml 2.9+ already disables external entity loading by default. Treat a version-guarded call under `PHP_VERSION_ID < 80000` as correct legacy support rather than a finding, and an unguarded call as a deprecation notice to clean up, not a missing protection
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
