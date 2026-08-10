# CWE-170: Improper Null Termination

## LLM Guidance

This weakness occurs when code that produces a C-style string fails to guarantee a terminating null byte at the true end of the data, most often because a bounded copy function that does not guarantee termination is used without an explicit terminator written afterward, or because data read from a network or file is treated as a string without ever being terminated. Downstream functions that scan for the terminator then read past the buffer's real end, leaking adjacent memory or crashing, or a terminator write itself lands out of bounds and corrupts memory. The fix is to guarantee, explicitly and on every path, that a buffer used as a string ends with a null terminator inside its real bounds.

## Key Principles

- Never assume a copy, read, or allocation wrote a terminator; only an explicit write is reliable
- Reserve the last byte of the destination when copying or reading so there is always room for the terminator
- Any buffer sized from a string's length must add space for the terminator, and every copy into it must respect that same accounting
- Data that was never a string to begin with (raw network or file reads) must be terminated explicitly at the position immediately after the last byte actually read
- Prefer a string type that tracks its own length and manages termination internally where the language and API surface allow it
- Do not rely on a buffer's prior contents or an assumption of zero-initialization to supply the terminator

## Remediation Steps

- Locate - Find bounded copy calls, network reads, and file reads that fill a buffer later treated as a C string
- Trace data flow - Follow the buffer from the source operation to every sink that scans for a terminator (string length, formatted output, comparison functions)
- Identify the unsafe pattern - A source operation that does not guarantee termination, with no explicit terminator write afterward
- Replace with the safe pattern - Reserve one byte of the destination for the terminator, then write it explicitly at the position immediately after the actual data
- Audit related allocations - Confirm any buffer sized from a string's length includes the extra byte the terminator needs
- Add secondary controls - Prefer copy/format functions that guarantee termination on every path, including truncation
- Test - Verify with input exactly at the buffer's capacity, one byte over, and empty input, and with reads that fill the buffer completely
