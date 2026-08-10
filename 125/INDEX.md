# CWE-125: Out-of-bounds Read

## LLM Guidance

An out-of-bounds read happens when a program reads data past the end, or before the beginning, of an allocated buffer or array, typically from a missing bounds check, an off-by-one condition, or a length or offset value taken from untrusted input without validation. It is almost exclusive to languages without automatic bounds checking, such as C and C++; managed languages instead throw an exception on out-of-range access. The fix is to validate the index, offset, and length against the buffer's actual size, checking both directions, before every read.

## Key Principles

- Validate that the index is non-negative and within size, and that offset plus length stays within the buffer, computed in a way that cannot itself overflow
- Check both the lower and upper bound; a negative index passing an upper-bound-only check still reads before the buffer
- Never trust a length or offset field taken directly from input, a file, or the network; validate it against the buffer's actual allocated or received size, not another claimed value from the same source
- Prefer bounds-checked accessor types over raw pointer arithmetic or unchecked indexing wherever available
- Add the bounds check immediately before the read, in the same function that performs it, not in an unrelated caller
- Apply defence-in-depth: run sanitizers and fuzzers against any function that reads from a buffer using an attacker-influenced offset or length

## Remediation Steps

- Locate - find the array index, pointer dereference, or copy operation performing the read, and the index, offset, or length value driving it
- Trace data flow - follow that value from its source (input, file, network, or a derived calculation) to the read
- Identify the unsafe pattern - a read performed without validating the index, offset, or length against the buffer's real size, or a bounds check written so an overflowing calculation can bypass it
- Replace with the safe pattern - add an explicit, overflow-safe bounds check immediately before the read, or switch to a bounds-checked accessor that enforces this automatically
- Add secondary controls - enable sanitizer and bounds-checking modes during development and testing to catch reads that slip past manual checks
- Test - test with oversized and negative index/offset/length values, values crafted to overflow the bounds-check calculation itself, and exact boundary values at size minus one, size, and size plus one
