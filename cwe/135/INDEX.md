# CWE-135: Incorrect Calculation of Multi-Byte String Length

## LLM Guidance

In native code a miscount driving an allocation or copy becomes memory corruption; in any language the same miscount makes a truncation point or a length-based limit admit more or less data than intended.

## Key Principles

- Never assume one byte equals one character; that only holds for pure ASCII
- Use byte length for buffer allocation and raw copy sizing
- Use a real character count, obtained by decoding the encoding, for user-facing limits and truncation
- Prefer an encoding-aware library or a runtime with native Unicode strings over hand-computed character counts from raw bytes
- Validate that byte sequences are well-formed for their declared encoding before trusting any count derived from them, and pass the encoding explicitly to every counting or conversion call - the wrong encoding hint miscounts silently rather than obviously
- Validate the length *after* decoding, transcoding, or normalizing: a raw string that passes a limit can expand or contract into a different count once processed
- Enlarging the buffer is not a fix - it makes the miscount less often visible as a crash while the same wrong unit still drives the validation check and the truncation point
- Truncate only on character boundaries, never at a raw byte offset that could split a multi-byte sequence

## Remediation Steps

- Locate - Find length calculations feeding a buffer allocation, copy operation, truncation point, or length-based validation check on text that may be non-ASCII
- Trace data flow - Identify which counting function produced the length and whether the consuming sink expects bytes or characters
- Identify the unsafe pattern - A byte-counting function's result used where a character count is required, or the reverse
- Replace with the safe pattern - Compute byte length and character count independently, each with the function suited to that unit, and route each to the operation that needs it
- Fix truncation logic - Ensure any cut point is derived from decoded character positions, not raw byte offsets
- Add secondary controls - Reject input containing malformed byte sequences for its declared encoding rather than counting it optimistically
- Test - Verify with strings where character count and byte count differ (CJK text, emoji, accented characters), at the length limit, one character over, and one byte over
