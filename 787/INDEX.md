# CWE-787: Out-of-bounds Write

## LLM Guidance

Out-of-bounds write occurs when a program writes data past the end, or before the start, of its allocated buffer, corrupting adjacent memory instead of failing safely. It typically stems from a missing bounds check, an incorrect size calculation, or a copy or format function that is not told the destination's real capacity. This is primarily a manual-memory-management issue in languages that allow raw pointer or unchecked array access; the fix is to validate every write against the destination's actual capacity and prefer bounds-checked abstractions over raw pointer or index arithmetic.

## Key Principles

- Prefer containers, spans, or buffer types that track their own capacity and reject an out-of-bounds write over raw arrays sized and indexed by hand
- Validate that offset plus length stays within the destination's real allocated size before every write, computed so the check itself cannot overflow
- Never trust a length or offset taken from user input, a file, or the network; validate it against the actual destination capacity, not the sender's claim
- Prefer copy and formatting functions that take an explicit destination capacity over ones that do not, and check that the operation completed as expected
- Harden the runtime with compiler and platform protections (stack protection, address space layout randomization) so a residual defect is harder to exploit
- Use sanitizers and fuzzing during development to catch bounds violations before release

## Remediation Steps

- Locate - Identify every raw memory write: array index assignment, pointer arithmetic, or a copy or format function writing into a fixed-size destination
- Trace data flow - Follow the length, offset, or index value back to its source and determine whether it is influenced by external input or an unchecked calculation
- Identify the unsafe pattern - Look for writes with no check that the write stays within the destination's allocated size, or a size calculation that can silently overflow before the write happens
- Replace with the safe pattern - Validate the write size against the destination's real capacity before the write, or switch to a bounds-checked container or function that enforces this automatically
- Add secondary controls - Enable compiler hardening flags and confirm copy or format calls check their result rather than assuming success
- Test - Exercise oversized, negative, and exact-boundary length or index values and confirm the write is rejected rather than performed out of bounds
