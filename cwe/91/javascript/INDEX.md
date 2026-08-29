# CWE-91: XML Injection (aka Blind XPath Injection) - JavaScript

## LLM Guidance

XML Injection in JavaScript/Node.js applications occurs when untrusted user input is used to construct XML documents without proper validation or escaping. Attackers can manipulate XML structure by injecting special characters like `<`, `>`, `&`, `'`, and `"`, leading to data corruption, authentication bypass, or information disclosure.

**Primary Defence:** Build the document with a library that escapes values - `xmlbuilder2`, or `fast-xml-builder`'s `XMLBuilder` - rather than assembling markup as a string. Each has a documented gap, so pick the fix against the one in use.

## Key Principles

- Build nodes with `create()`/`.ele()` and set values with `.txt()`/`.att()` rather than concatenating markup
- **`xmlbuilder2` does not escape every ampersand.** Its text encoder skips a `&` already followed by `[A-Za-z]+;` or `#\d+;`, so `.txt('&lt;script&gt;')` is emitted verbatim and a conforming parser hands the consumer back `<script>`. Where the value can contain entity-shaped text, escape the ampersand before it reaches `.txt()`, or check the consumer decodes only what you intend
- **`.ele()` with a single string argument parses it as markup**, not as an element name - `.ele('<foo><bar/></foo>')` inserts that subtree. Never pass an untrusted string in that position; use the `.ele(name)`/`.txt(value)` split
- `xmlbuilder2` validates names and throws for an invalid one, so an attacker-chosen *name* that is malformed fails loudly rather than injecting - but a name that is a valid XML name still lets the attacker choose which element gets created, so allowlist it. `fast-xml-builder` does not validate at all: its `sanitizeName` defaults to `false`
- `fast-xml-builder` escapes all five characters by default, but the escaping is defeasible - `processEntities: false` turns it off wholesale, and any tag listed in `stopNodes` is written as raw content. Check both options before treating the builder as the control. Note also that the `XMLBuilder` re-exported from `fast-xml-parser` is a compatibility shim the vendor has announced for removal; depend on `fast-xml-builder` directly
- Escape XML special characters where you escape by hand: `&` -> `&amp;`, `<` -> `&lt;`, `>` -> `&gt;`, `'` -> `&apos;`, `"` -> `&quot;`. Only `&` and `<` carry an unconditional requirement in character data; the quotes matter inside attribute values, and `>` matters where it would complete `]]>`
- None of the five entities makes a value CDATA-safe. `xmlbuilder2`'s `.dat()` throws on a payload containing `]]>` rather than splitting it, so handle that rejection instead of assuming the value is written; `xmlbuilder` v1 and `xml2js` split it into two sections instead
- The predecessor library `xmlbuilder` v1 has a `.raw()`/`.r()` method documented as not escaping; `xmlbuilder2` removed it deliberately. Treat any remaining `.raw()` call as the sink
- Where you escape by hand, `he.encode()` is the maintained option, but leave `useNamedReferences` at its default `false` - setting it true emits HTML5 named entities such as `&nbsp;`, and a strict XML parser with no DOCTYPE fails the document with "Entity nbsp not defined"
- Check which `xmldom` is installed: the unscoped package has not been published since 2021 and carries unfixed advisories, one of them an XML injection through CDATA serialization. Use `@xmldom/xmldom`
- Where the finding is a value concatenated into an XPath *query* rather than into a document, that is CWE-643
- A `DOCTYPE`, external-entity or entity-expansion finding is CWE-611, not this one, and hardening the parser does nothing for a document built by concatenation

## Taint Sinks

Template literals/string concatenation building XML, `xmlbuilder` v1 `.raw()`/`.r()`, `xmlbuilder2` `.ele(xmlString)`, `XMLBuilder` with `processEntities: false` or a `stopNodes` entry

## Remediation Steps

- Replace string concatenation XML building with library-based node construction
- Identify which builder is in use and apply its specific gap: the ampersand rule and the `.ele(string)` overload for `xmlbuilder2`, the `processEntities`/`stopNodes`/`sanitizeName` options for `fast-xml-builder`
- Allowlist any element or attribute name taken from input, separately from the value escaping
- Validate input against strict schemas or patterns before processing
- Test with payloads containing `<`, `>`, `&`, a pre-encoded entity such as `&lt;script&gt;`, and `]]>` where a CDATA section is written - and assert on what a parser recovers from the output, not on the output string
