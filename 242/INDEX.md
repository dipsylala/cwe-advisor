# CWE-242: Use of Inherently Dangerous Function

## LLM Guidance

This weakness appears when code calls a function that has no safe usage pattern at all, because its signature omits information (such as a destination buffer's capacity) that any caller would need to use it safely, regardless of how carefully surrounding code is written. The remediation is not to add validation around the call; no amount of caller-side checking changes what the function itself does. The function must be replaced with an alternative whose signature requires the missing safety information, such as an explicit destination size or length limit, and the dangerous function should be banned outright so it cannot reappear.

## Key Principles

- Primary defence: replace the dangerous function with an alternative that takes the safety-relevant information (destination capacity, length limit) as a required argument.
- Do not attempt to "fix" the dangerous function by wrapping it in a size check or an assumption about input length; the function itself has no way to honor that boundary.
- Treat this as a function-level ban, not a per-call-site review; every call to the dangerous function is equally unsafe.
- Apply the same replacement to every existing call site, not only newly written code.
- Defence-in-depth: enforce the ban with a compiler-level or static-analysis deny list so a reintroduced call fails the build rather than depending on manual review.

## Remediation Steps

- Locate - Search the codebase for every call to a function on the language's inherently-dangerous or prohibited-function list.
- Trace data flow - Identify the fixed-size destination (buffer, array) each call writes into and confirm the function's signature has no parameter for that destination's capacity.
- Identify the unsafe pattern - Confirm the call has no way for the caller to bound the operation; this is the defining trait of this weakness, distinct from a function that is merely easy to misuse.
- Replace with the safe pattern - Substitute a bounded alternative from the platform's standard library that takes the destination capacity or a length limit as a required argument.
- Add secondary controls - Add the banned function to a compiler-enforced or static-analysis deny list so any reintroduction fails the build automatically.
- Test - Provide input longer than the destination buffer and confirm the replacement truncates or rejects it rather than overflowing.
- Verify - Re-run static analysis or a repository-wide search to confirm no remaining calls to the banned function exist anywhere in the codebase.
