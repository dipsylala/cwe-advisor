# CWE-121: Stack-based Buffer Overflow

## LLM Guidance

A stack-based buffer overflow happens when more data is written into a fixed-size, stack-allocated buffer than it was declared to hold, corrupting adjacent stack memory including, potentially, the saved return address. It is specific to languages without automatic bounds checking on buffer writes, primarily C and C++. The fix is to validate the incoming data's length against the destination buffer's actual capacity before every copy, and to prefer copy or format functions that enforce a size limit over ones that do not.

## Key Principles

- Never copy or format data into a fixed-size stack buffer without first checking the source length against the destination's declared capacity
- Prefer length-limited copy or format functions that take an explicit size argument and check for truncation over unbounded equivalents
- Use the destination buffer's actual declared size in the length check, never a separate hardcoded constant that can drift out of sync
- Prefer a dynamically-sized, self-managing buffer or string type over a fixed-size stack array unless the maximum size is small and genuinely fixed
- Reject oversized input explicitly rather than silently truncating it
- Check the new bound carefully: `<=` where `<` was needed, or forgetting to reserve a byte for the string terminator, permits exactly the one byte that overflows
- A length check at an outer boundary does not cover a second copy deeper in the call stack: re-check at each function that writes into a fixed-size buffer, since that function may also be reachable from another caller
- Apply defence-in-depth: enable stack canaries, ASLR, and non-executable stack protections, understanding these reduce exploitability but do not fix the underlying write

## Remediation Steps

- Locate - find the fixed-size stack buffer and the copy, format, or manual loop that writes into it
- Trace data flow - follow the length of the incoming data from its source (user input, file, network) to the point of the write
- Identify the unsafe pattern - an unbounded copy or format function, or a bounded one whose size argument does not actually reflect the destination buffer's real capacity
- Replace with the safe pattern - validate that the input length fits within the buffer size before the copy, reserving room for a terminator if the data is a string, or switch to a copy function that enforces the destination size internally
- Add secondary controls - enable compiler and runtime hardening such as stack canaries, ASLR, and a non-executable stack as an additional layer, not a substitute for the fix
- Test - test at the buffer's exact capacity, one byte over, and far over; fuzz the entry point; confirm with a memory sanitizer that no out-of-bounds write occurs, not just that the program did not crash
