# CWE-611: Improper Restriction of XML External Entity Reference - JavaScript

## LLM Guidance

XXE injection occurs when XML parsers process external entity references, allowing attackers to read local files, perform SSRF attacks, or cause denial of service. Establish first whether the parser in use can resolve an external entity at all, because most of the common Node parsers cannot: `xml2js` sits on `sax-js`, which never implemented DTD fetching, and `fast-xml-parser` expands only in-document DOCTYPE entities. That makes the usual Node finding a denial-of-service one - entity expansion - rather than the file-disclosure and SSRF form seen in Java or PHP. `libxmljs` binds libxml2 and is the exception that can genuinely fetch, and it is also unmaintained with unfixed advisories.

## Key Principles

- Disable external entity processing and DTD resolution in all XML parser configurations
- Use secure XML parsing libraries with XXE protection enabled by default
- Validate and sanitize XML input before parsing, rejecting suspicious patterns
- Prefer JSON over XML for data exchange when architecturally feasible

## Taint Sinks

`libxmljs.parseXml()`, `xml2js.parseString()`, `fast-xml-parser` with entity processing enabled

## Remediation Steps

- Do not reach for `libxmljs` as the safe parser. It carries CVE-2024-34391 with no patched release,
  its `libxmljs2` fork carries CVE-2024-34394 with no fix and its repository is gone, and the option
  names often quoted for it (`noent`, `dtdload`, `dtdvalid`) belong to the older API - current
  `libxmljs` deprecates `noent` in favour of `replaceEntities`. Where a project already depends on it,
  the finding to raise is the dependency, not the parser options
- `xml2js` is built on `sax-js`, which never implemented DTD fetching at all, so external entities are
  absent rather than disabled and there is no option to set. Its 0.5.0 floor is real but belongs to a
  different weakness - prototype pollution, CVE-2023-0842 - so cite it there and not here
- Set `fast-xml-parser` with `processEntities - false` option
- Review all XML parsing code and apply secure configurations consistently
- Add input validation to reject XML containing DOCTYPE declarations or entity references
