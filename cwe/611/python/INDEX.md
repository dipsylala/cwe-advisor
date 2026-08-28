# CWE-611: Improper Restriction of XML External Entity Reference - Python

## LLM Guidance

Establish the Python version before treating this as a live finding. CPython's XML parsers were
hardened in 3.6.8 and 3.7.1, and the standard library's own security notes now state that Expat does
not access local files or create network connections by default - so `xml.etree`, `xml.dom` and
`xml.sax` on a supported Python do not resolve external entities, and a rule that flags them is
usually reporting the pre-3.7 world. Two concerns remain live: `lxml`, which does substitute entities
by default, and entity-expansion denial of service on a build carrying Expat older than 2.7.2.

**Primary Defence:** Fix the parser that is actually unsafe - pass `resolve_entities=False` to
`lxml.etree.XMLParser` - and confirm the interpreter's Expat version rather than replacing standard
library calls that are already safe.

## Key Principles

- `lxml` is the parser that still needs configuring: `resolve_entities` is documented as on by
  default, so `resolve_entities=False` on the `XMLParser` is the change that matters. `no_network` is
  *already* on by default, so setting it is not the fix even though it often appears alongside
- Check `pyexpat.EXPAT_VERSION`. Below 2.7.2 the billion-laughs, quadratic-blowup and large-token
  protections are absent, which makes this a denial-of-service finding rather than a disclosure one,
  and the remedy is upgrading the interpreter or its system Expat rather than editing parser calls
- `defusedxml` still works, but check before adding it: its last release was 0.7.1 in 2021 and its own
  README marks `defusedxml.lxml` deprecated for removal. On a supported Python the standard library
  equivalents no longer need wrapping, so introducing the dependency adds maintenance for no gain
- `xmlrpc` remains documented as vulnerable to a decompression bomb, so an XML-RPC endpoint taking
  untrusted input is a separate finding from the parser question
- Where the XML comes from a trusted internal service, say so at the call site; the fix for a parser
  that is already safe by default is to record why, not to add configuration that does nothing

- Hardening usually makes the reference expand to nothing rather than rejecting the document: the
  parse succeeds, the element is empty, and a handler that treats a missing value as optional carries
  on with silently wrong data. Where the document must be refused rather than emptied, install a
  resolver that throws, and check for an absent value on every element read

## Taint Sinks

`lxml.etree.parse()`/`fromstring()` with a default parser, `lxml.etree.XMLParser(resolve_entities=True)`,
`xmlrpc.client`/`xmlrpc.server` on untrusted input, and `xml.etree.ElementTree.parse()`,
`xml.dom.minidom.parse()`, `xml.sax.parse()` only on Python below 3.7.1

## Remediation Steps

- Establish the interpreter version first - on a supported Python the standard-library parsers are
  not the finding, and the work is in `lxml` and in the Expat version
- Where a legacy interpreter or a hostile-input boundary still warrants it, `defusedxml` remains a
  drop-in - `from defusedxml.ElementTree import parse` - but check its maintenance status first
- For `lxml`, configure the parser directly with `resolve_entities=False`, `no_network=True`, and `load_dtd=False`
- Note `forbid_dtd`, `forbid_entities` and `forbid_external` are `defusedxml`'s own arguments, not
  standard-library ones, so they are not the fallback for when it is unavailable - two of the three
  are already its defaults
- Review all XML parsing code paths for unsafe configurations
- Add security tests with XXE payloads to validate protections
