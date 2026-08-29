# CWE-91: XML Injection (aka Blind XPath Injection) - Python

## LLM Guidance

XML Injection occurs when untrusted input is used to construct XML documents without proper validation or escaping, allowing attackers to manipulate XML structure using special characters (`<`, `>`, `&`, `'`, `"`). This can lead to data corruption, authentication bypass, or information disclosure.

**Primary Defence:** Use `xml.etree.ElementTree` or `lxml` element creation methods instead of string concatenation, and let the serializer do the escaping.

## Key Principles

- Never construct XML documents using string concatenation or formatting with user input
- Element APIs escape at *serialization*, not at assignment: `.text` and `.set()` store the raw string, and `ElementTree.tostring()` is what replaces `<`, `>`, `&` in text and adds `"` in attribute values. A tree that is written out by hand rather than by the library keeps none of that
- **Neither library escapes names, and only one rejects them.** ElementTree accepts `SubElement(parent, "bad name<x>")` and emits malformed XML; `lxml.etree` raises `ValueError: Invalid tag name`. The same split applies to `Comment` and `ProcessingInstruction`, which ElementTree writes unescaped. Allowlist any name that comes from input rather than relying on the library to notice - lxml's rejection covers a malformed name, not an attacker choosing among valid ones
- `xml.sax.saxutils.escape()` escapes only `&`, `<` and `>`. It does **not** escape either quote, so it is not sufficient for an attribute value. Use `xml.sax.saxutils.quoteattr()` there - note it returns the value *with* the surrounding quote characters, so write `attr=%s` and not `attr="%s"`
- No escaping makes a value CDATA-safe. ElementTree has no CDATA support at all; `lxml.etree.CDATA()` splits an embedded `]]>` across two sections, which is undocumented behaviour rather than a stated contract
- Where the finding is a value concatenated into an XPath *query* rather than into a document, that is CWE-643 - `lxml` binds natively there, with `tree.xpath("//user[@name=$name]", name=value)`
- A `DOCTYPE`, external-entity or entity-expansion finding is CWE-611, not this one, and hardening the parser does nothing for a document built by concatenation. Do not reach for `defusedxml` here: it is parse-side only, its last stable release is 0.7.1 (March 2021), its `defusedxml.lxml` module is marked deprecated, and CPython's own documentation dropped the recommendation in 3.13

## Taint Sinks

f-string/`.format()`/`%`-formatted XML strings, `+` concatenation into raw XML, `xml.sax.saxutils.escape()` used on an attribute value

## Remediation Steps

- Replace string concatenation with `ElementTree.Element()` and `SubElement()` methods, or the `lxml.etree` equivalents
- Use `.text` and `.set()` to assign content and attributes, and serialize with `tostring()`/`ElementTree.write()` rather than emitting the tree yourself
- Allowlist any element or attribute name taken from input; prefer `lxml` where names are dynamic, since it rejects an invalid one
- Where manual construction is unavoidable, use `saxutils.escape()` for element content and `saxutils.quoteattr()` for attribute values - they are not interchangeable
- Review all XML generation code paths for user input handling
- Test with the metacharacters, with a value containing both quote styles in an attribute, and with `]]>` where a CDATA section is written
