# CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer

## LLM Guidance

This is the general buffer-bounds weakness: a read, write, or pointer/index operation on a buffer, array, or memory region proceeds without confirming the computed index, offset, or length stays within the region's actual allocated bounds. It covers both directions - reading past the end (CWE-125) and writing past the end (CWE-787) - plus cases where the operation could do either, such as a generic memcpy-style call driven by an untrusted or miscalculated size. If you can tell whether the operation is a read or a write, prefer the more specific CWE-787 or CWE-125 guidance; use this entry when the operation is mixed, unclear, or you are addressing the class as a whole rather than one call site.

## Key Principles

- Track the true allocated size of every buffer alongside the buffer itself, and keep it in sync across reallocations, truncations, or reslicing
- Prefer bounds-checked container and view types over raw pointer arithmetic or hand-indexed arrays - for example, C++ `std::span` or `std::vector::at()`, or Rust slices - which fail safely on out-of-range access instead of touching adjacent memory
- Perform any arithmetic used to compute an index, offset, or length with checked or overflow-safe operations; an integer overflow in the size calculation can defeat an otherwise-correct bounds check
- Never trust a length, offset, or index from user input, a file, or the network; validate it against the buffer's actual allocated size, not another value from the same untrusted source
- This weakness is almost exclusive to languages with manual memory management and unchecked indexing, such as C and C++; memory-safe languages enforce bounds automatically, so remediation there is usually about avoiding `unsafe`/native interop rather than adding checks
- Apply defence-in-depth: compiler and runtime hardening (AddressSanitizer, `-fsanitize=bounds`, stack protection) and fuzzing catch violations that slip past manual review

## Remediation Steps

- Locate - find every buffer, array, or pointer operation whose index, offset, or length is not a compile-time constant
- Classify - determine whether each operation is a read, a write, or both, routing read-only findings to CWE-125 and write findings to CWE-787 for detailed steps; where the overflowed buffer is plainly a local array, CWE-121 carries the stack-specific guidance
- Trace data flow - follow the index, offset, or length back to its source and note whether external input or a derived calculation influences it
- Identify the unsafe pattern - raw pointer arithmetic or unchecked indexing with no validation against the buffer's real capacity, or a bounds check whose own arithmetic can overflow
- Replace with the safe pattern - use a bounds-checked container, span, or accessor type where available, or add an explicit, overflow-safe bounds check immediately before the operation
- Add secondary controls - enable sanitizer and bounds-checking builds in CI, and fuzz any function touching a buffer with an attacker-influenced offset or length
- Test - exercise oversized, negative, and exact-boundary values, plus values crafted to overflow the bounds-check arithmetic itself, and confirm the operation is rejected rather than performed out of bounds
