# CWE-115: Misinterpretation of Input

## LLM Guidance

This weakness occurs when two or more layers that process the same input, such as a validator and an executor, or a proxy and a backend, interpret it differently, letting an attacker craft input that passes validation under one interpretation while executing under another. It commonly underlies HTTP request smuggling, encoding-based filter bypass, and validation/execution mismatches. The fix is to make every layer parse the input identically, and to validate the exact form of data that will actually be used, not an earlier or alternate representation of it.

## Key Principles

- Normalize or canonicalize input once, then validate and act on that same canonical value everywhere downstream
- Never validate one representation of the input (raw bytes, a given encoding) while executing against a different one
- Use a single, shared parser or decoder for a given input type across all layers that touch it, such as a proxy and the application behind it
- Reject ambiguous input outright rather than guessing an interpretation: conflicting headers, mixed encodings, non-canonical byte sequences
- Enforce exact-match validation (Content-Type, encoding declarations) rather than prefix or fuzzy matching that tolerates parser-disagreement-prone variants
- Apply defence-in-depth: log and alert on rejected ambiguous input to detect probing

## Remediation Steps

- Locate - find every point where the same input is parsed, decoded, or interpreted more than once across layers or components
- Trace data flow - determine whether the validation step and the execution step parse the value with the same logic and produce the same result
- Identify the unsafe pattern - a validation check performed on a different representation (raw vs decoded, one encoding vs another, pre- vs post-normalization) than the one the executing layer actually acts on
- Replace with the safe pattern - normalize or canonicalize first, then validate the canonical form, then use that same canonical value for execution
- Add secondary controls - reject requests or input with conflicting or ambiguous framing (dual Content-Length/Transfer-Encoding, mixed encodings, non-canonical sequences) instead of attempting to reconcile them
- Test - submit input whose interpretation differs only after normalization or decoding, and confirm validation and execution agree on every case; retest through the full chain of components, not a single layer in isolation
