# CWE-118: Incorrect Access of Indexable Resource ('Range Error')

## LLM Guidance

This is MITRE's broad umbrella for any out-of-range access to an indexable resource such as an array, buffer, string, or stream, and it is discouraged for direct mapping; prefer the specific descendant when known, such as out-of-bounds read, out-of-bounds write, stack-based buffer overflow, out-of-range pointer offset, or uninitialized pointer access. Use this page only when a finding names CWE-118 directly with no more specific classification available. The universal fix is to validate any index, offset, or length against the resource's actual current size immediately before the access.

## Key Principles

- Validate index, offset, and length against the resource's real, current size before every access, not a size cached earlier
- Prefer bounds-checked types and accessor methods over manually tracked raw indexing wherever the language or library offers them
- Never trust a length or count that travels alongside the data it describes, such as a size prefix in a file or network message; validate it against the actual allocated or received size
- Reject out-of-range access explicitly; do not silently clamp an invalid index into range (`index = min(index, size - 1)`), which accesses the wrong element instead of refusing the request and can itself produce security-relevant wrong answers
- Where the untrusted value is the index itself rather than a missing check on the access, CWE-129 is the closer fit - MITRE files it outside this hierarchy because the root cause there is missing input validation
- Check both the lower and upper bound; a negative index is a distinct failure mode from one that is too large
- Apply defence-in-depth: handle bounds-check exceptions from managed languages gracefully rather than letting them become an unhandled crash

## Remediation Steps

- Locate - identify the specific descendant weakness the finding actually represents (read vs write, stack vs heap) and prefer its dedicated guidance if it exists
- Trace data flow - follow the index, offset, or length value from its source (input, calculation, stored size) to the point of access
- Identify the unsafe pattern - an indexed access, slice, or seek performed without checking the value against the resource's actual bounds
- Replace with the safe pattern - add an explicit range check immediately before the access, or switch to a bounds-checked abstraction that enforces this automatically
- Add secondary controls - recompute or re-check size at the point of access rather than trusting a value computed earlier, since the resource can change between the two points
- Test - use boundary values (last valid index, first invalid index), negative indices, and attacker-influenced length calculations, including values crafted to overflow the calculation itself
- Treat the reported access as a sample: the same unchecked-index pattern usually repeats across sibling operations in the same function or module
