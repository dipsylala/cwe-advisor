# CWE-115: Misinterpretation of Input

## LLM Guidance

This weakness occurs when two or more layers that process the same input, such as a validator and an executor, or a proxy and a backend, interpret it differently, letting an attacker craft input that passes validation under one interpretation while executing under another. It commonly underlies HTTP request smuggling, encoding-based filter bypass, and validation/execution mismatches. The fix is to make every layer parse the input identically, and to validate the exact form of data that will actually be used, not an earlier or alternate representation of it.

## Key Principles

- Normalize or canonicalize input once, then validate and act on that same canonical value everywhere downstream
- Never validate one representation of the input (raw bytes, a given encoding) while executing against a different one
- Use a single, shared parser or decoder for a given input type across all layers that touch it, such as a proxy and the application behind it
- Reject ambiguous input outright rather than guessing an interpretation: a request carrying both `Content-Length` and `Transfer-Encoding`, several differing `Content-Length` fields, a `Transfer-Encoding` where `chunked` is not the final coding, or an obfuscated one (`xchunked`, whitespace before the colon, the header sent twice) should be answered with 400. RFC 9112 allows a server either to reject or to honour `Transfer-Encoding` alone; rejecting is the option that does not depend on the next hop having chosen the same way
- Enforce exact-match validation (Content-Type, encoding declarations) rather than prefix or fuzzy matching that tolerates parser-disagreement-prone variants
- Apply defence-in-depth: log and alert on rejected ambiguous input to detect probing

## Remediation Steps

- Locate - find every point where the same input is parsed, decoded, or interpreted more than once across layers or components
- Trace data flow - determine whether the validation step and the execution step parse the value with the same logic and produce the same result
- Identify the unsafe pattern - a validation check performed on a different representation (raw vs decoded, one encoding vs another, pre- vs post-normalization) than the one the executing layer actually acts on
- Replace with the safe pattern - normalize or canonicalize first, then validate the canonical form, then use that same canonical value for execution
- Add secondary controls - an intermediary that does forward such a request must strip `Content-Length` and re-emit the body from the decoded `Transfer-Encoding`, so the back end never sees a second framing to disagree about; forwarding both unchanged is what hands it the ambiguity
- Close the connection after any framing error rather than returning it to the keep-alive pool: a socket that has just been mis-parsed holds bytes the next request inherits as a prefix, so a 400 on a connection that stays open still leaves the smuggled bytes queued
- Test - submit input whose interpretation differs only after normalization or decoding (`....//`, `%252e%252e%252f`), send both framing headers and confirm a 400 *and* that the connection closes, submit overlong UTF-8 and near-match content types, and confirm a differently-cased `Application/JSON` is still accepted; retest through the full chain, not a single layer in isolation, and again after any hop is upgraded
