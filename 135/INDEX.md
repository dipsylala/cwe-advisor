# CWE-135: Incorrect Calculation of Multi-Byte String Length

## LLM Guidance

This weakness occurs when code measures a string with a byte-counting function but treats the result as a character count, or the reverse - most commonly assuming one byte equals one character for text that may contain multi-byte encoded (UTF-8, UTF-16) characters. In native code, a miscounted length that drives a buffer allocation or copy causes memory corruption. In any language, using the wrong unit for a truncation point or a length-based validation check produces malformed text or lets more or less data through a limit than intended. The fix is to keep byte length and character count as two distinct values and use whichever one the specific operation actually needs.

## Key Principles

- Never assume one byte equals one character; that only holds for pure ASCII
- Use byte length for buffer allocation and raw copy sizing
- Use a real character count, obtained by decoding the encoding, for user-facing limits and truncation
- Prefer an encoding-aware library or a runtime with native Unicode strings over hand-computed character counts from raw bytes
- Validate that byte sequences are well-formed for their declared encoding before trusting any count derived from them
- Truncate only on character boundaries, never at a raw byte offset that could split a multi-byte sequence

## Remediation Steps

- Locate - Find length calculations feeding a buffer allocation, copy operation, truncation point, or length-based validation check on text that may be non-ASCII
- Trace data flow - Identify which counting function produced the length and whether the consuming sink expects bytes or characters
- Identify the unsafe pattern - A byte-counting function's result used where a character count is required, or the reverse
- Replace with the safe pattern - Compute byte length and character count independently, each with the function suited to that unit, and route each to the operation that needs it
- Fix truncation logic - Ensure any cut point is derived from decoded character positions, not raw byte offsets
- Add secondary controls - Reject input containing malformed byte sequences for its declared encoding rather than counting it optimistically
- Test - Verify with strings where character count and byte count differ (CJK text, emoji, accented characters), at the length limit, one character over, and one byte over
