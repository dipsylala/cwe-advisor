# CWE-611: Improper Restriction of XML External Entity Reference - C#

## LLM Guidance

XXE vulnerabilities in .NET occur when XML parsers process external entity references in untrusted XML, enabling file disclosure, SSRF, and DoS attacks. The safe defaults are dated per API rather than per runtime, and the split is not Core-versus-Framework: `XmlReaderSettings.DtdProcessing` has defaulted to `Prohibit` since .NET Framework 4.0, and `XmlReaderSettings.XmlResolver` to `null` since .NET Framework 4.5.2. `XmlDocument` is the real exception - Microsoft documents no null default for its `XmlResolver`, and states that when the document is not loaded through an `XmlReader` its own resolver is always used.

**Primary Defence:** Set `DtdProcessing = DtdProcessing.Prohibit` and `XmlResolver = null` in `XmlReaderSettings`.

## Key Principles

- Prohibit DTD processing entirely using `DtdProcessing.Prohibit` to reject DOCTYPE declarations
- Set `XmlResolver = null` to block external entity resolution even if DTDs bypass other controls
- Apply secure settings to all XML parsing APIs (XmlDocument, XmlReader, XmlSerializer, DataContractSerializer)
- Keep DTD processing prohibited; if entity expansion is allowed for trusted XML, set a positive `MaxCharactersFromEntities` limit, whose default of 0 means no limit at all - noting Microsoft scopes that property to denial of service rather than to disclosure and consider `MaxCharactersInDocument`
- Create reusable secure configuration helpers to ensure consistent protection across the codebase

## Taint Sinks

`XmlDocument.LoadXml()`, `XmlReader.Create()` without secure settings, `XmlSerializer.Deserialize()`, `DataContractSerializer`

## Remediation Steps

- Identify all XML parsing locations (XmlDocument.LoadXml, XmlReader.Create, XmlSerializer.Deserialize, etc.)
- Create `XmlReaderSettings` with `DtdProcessing = DtdProcessing.Prohibit` and `XmlResolver = null`
- Replace direct XML parsing calls with secure XmlReader-wrapped patterns
- For `XmlDocument`, explicitly set `doc.XmlResolver = null`. This is the one place the defaults do not
  cover: loaded without an `XmlReader`, the document always uses its own resolver, and a resolver set
  on a reader is not retained by the document after `Load` returns
- Test with XXE payloads (<!DOCTYPE, SYSTEM entities) to verify rejection
- Validate legitimate XML workflows still function correctly after hardening
