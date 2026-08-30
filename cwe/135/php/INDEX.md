# CWE-135: Incorrect Calculation of Multi-Byte String Length - PHP

## LLM Guidance

PHP's `strlen()`, `substr()`, `strpos()` and friends operate on bytes, and a UTF-8 character outside ASCII occupies 2-4 of them. PHP strings are managed, so this does not corrupt memory the way C does, but the byte/character confusion still causes real defects: a limit written as "N characters" and enforced with `strlen()` rejects non-ASCII text well short of N, the reverse pairing sends up to four times the bytes a byte-sized column expected, and `substr()` truncation splits a sequence and produces invalid UTF-8. Use the character-aware `mb_*` functions for any string that may contain non-ASCII input.

## Key Principles

- Use `mb_strlen($s, 'UTF-8')` for a user-facing length limit and `strlen($s)` for a storage-size limit - keep both, and do not let one stand in for the other. A `strlen()` hit against a genuine byte limit (a fixed-size column, a `Content-Length` check) is correct code, not a defect - converting every `strlen()` call to `mb_strlen()` on sight breaks the byte-limit case
- A byte count used as a character-count limit only over-rejects, never overflows: UTF-8 byte count is never smaller than character count, so this surfaces as "my bio is too long" complaints rather than a security finding. If a single business rule (e.g. "100 characters") is enforced at more than one call site, fixing the display-facing `substr()`/`mb_substr()` call while a separate validation check elsewhere still counts with `strlen()` leaves that second site silently wrong
- Truncate with `mb_substr()`, which cuts on a character boundary, so the result is always valid UTF-8; `substr()` can leave a half-encoded sequence that later breaks JSON encoding, an XML response, or a database write
- Pass the encoding explicitly to every `mb_*` call, or set it once with `mb_internal_encoding('UTF-8')`, rather than depending on an ini default that differs between environments
- Validate that the input is well-formed with `mb_check_encoding($s, 'UTF-8')` before measuring or slicing it - a count taken over invalid bytes is meaningless, and `mb_convert_encoding()` will silently substitute characters
- Use `mb_strpos`/`mb_str_split`/`mb_strtolower` where offsets or case are involved; the byte versions return offsets that cannot be fed back into the `mb_*` family
- A code point is still not a user-perceived character: an emoji with a modifier or a combining accent counts as several. Where the limit is about display, normalise first and document what is being counted
- A `VARCHAR(255)` column limit is always 255 characters regardless of charset, but MySQL/MariaDB also cap total row size at 65,535 bytes - a `utf8mb4` column can need up to 4 bytes per character, so a form of several such columns can fail on the row-size limit even though each column's own character limit was respected. Check both before writing
- `preg_*` needs the `u` modifier to treat the subject as UTF-8; without it a pattern matches bytes and `.` can split a character

## Taint Sinks

`strlen()` used as a character count, `substr()`, `str_pad()`, `strpos()`, `wordwrap()`, `preg_match()` without the `u` modifier, a database write sized from the wrong unit

## Remediation Steps

- Locate - find length checks, truncations, and offset arithmetic applied to text that can contain non-ASCII input
- Trace data flow - determine whether each limit is a display limit (characters) or a storage limit (bytes), and which function is enforcing it
- Identify the unsafe pattern - `strlen()` behind a "characters" limit, `substr()` truncation of user text, or `preg_*` without `u`
- Replace with the safe pattern - `mb_strlen`/`mb_substr` with an explicit encoding for the character-facing rules, keeping `strlen` for storage rules
- Bind, encode, validate, or authorize - reject input failing `mb_check_encoding()` rather than converting it silently
- Harden configuration - set `mb_internal_encoding('UTF-8')` at bootstrap, ensure the database connection and columns are `utf8mb4`, and add the `u` modifier to the relevant patterns
- Test - submit text containing 2-, 3- and 4-byte sequences and an emoji, and assert the limit rejects at the intended count, the truncated value is valid UTF-8, and the database write succeeds
