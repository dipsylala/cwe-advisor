# CWE-611: Improper Restriction of XML External Entity Reference (XXE) - Go

## LLM Guidance

Go's standard `encoding/xml` package does not resolve external SYSTEM/PUBLIC entities or expand DTDs, so `xml.Unmarshal` and `xml.NewDecoder(...).Decode` on their own do not produce the classic file-disclosure or SSRF form of XXE the way some other languages' parsers do. Risk in Go comes from three places: forwarding accepted DTD-bearing XML to a different component that does resolve entities (a downstream service, a CGo-based `libxml2` binding, or a third-party parser), populating `xml.Decoder.Entity` from untrusted input, or reimplementing entity expansion in application code (e.g. a regex that reads files for `SYSTEM` references). Confirm which parser handles the data at every hop, not just the first one.

## Key Principles

- Confirm `encoding/xml` is the parser used end-to-end; do not assume its safe defaults extend to any component the raw XML is later forwarded to, logged, or re-parsed by
- Reject XML containing `<!DOCTYPE` or `<!ENTITY` declarations at the input boundary when the API contract does not require them, as defense-in-depth beyond relying on parser behavior alone
- Avoid third-party or CGo-based XML libraries (`libxml2` bindings, `expat` wrappers) for untrusted input unless they can be explicitly configured to disable DTD loading and external entity resolution
- Never populate `xml.Decoder.Entity` from untrusted document content; keep it a small, fixed, application-defined substitution map or omit it entirely
- Never reimplement `SYSTEM`/`PUBLIC` entity expansion in application code (e.g. regex-based substitution that reads local files); this recreates the vulnerability `encoding/xml` avoids
- Apply `http.MaxBytesReader` or `io.LimitReader` consistently on every XML input path, including
  streaming `Decoder.Token()` loops and not only the `Unmarshal` path. Be clear about what that buys:
  a byte cap bounds input size, not recursion depth, and Go's XML denial-of-service issues have been
  depth ones - a small, deeply nested document still exhausts the stack. Those are fixed by keeping
  the toolchain current (CVE-2022-28131 and CVE-2022-30633, then a `DecodeElement` regression that
  reset the depth counter, fixed August 2026), so treat patching Go as part of this remediation

- A `containsDOCTYPE` byte-scan is a filter with a precondition: a document encoded as UTF-16 contains
  no literal `<!DOCTYPE` byte sequence and passes it untouched, so decode to a known encoding first or
  reject encodings the format does not need

## Taint Sinks

`xml.Unmarshal()`, `xml.NewDecoder().Decode()`, `Decoder.Token()`, CGo `libxml2`/`expat` bindings

## Remediation Steps

- Locate - Find every `xml.Unmarshal`, `xml.NewDecoder`, third-party XML parser call, or CGo `libxml2`/`expat` binding that processes request bodies, uploaded files, or other untrusted XML
- Trace data flow - Follow the raw XML bytes (not just the decoded struct) to confirm whether they are forwarded, logged, queued, or re-parsed by a different component downstream
- Replace the unsafe pattern - Route untrusted XML exclusively through `encoding/xml`; remove or isolate CGo/third-party parsers from untrusted input paths
- Bind, encode, validate, or authorize - Decode into a narrow, explicitly-typed struct with `xml:"..."` tags; validate required fields after decoding before using the data
- Break taint after allowlist validation - If a DOCTYPE/ENTITY-rejection check runs before parsing, act on the validated byte slice consistently rather than re-reading the original request body elsewhere
- Harden configuration - Wrap the reader in `http.MaxBytesReader(w, r.Body, limit)` or `io.LimitReader`; add a `containsDOCTYPE` byte-scan rejecting `<!DOCTYPE`/`<!ENTITY` before `xml.Unmarshal` if the format never needs them
- Test - Submit a payload with `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` and confirm it is rejected or the entity is not expanded; verify oversized payloads are rejected on every XML entry point, including streaming decoders
