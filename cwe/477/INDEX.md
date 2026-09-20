# CWE-477: Use of Obsolete Function

## LLM Guidance

This entry is about *status* - withdrawn, deprecated, or superseded - so the fix is a substitution, because an obsolete function has a named successor. A current function with a documented safe calling convention (`strcpy`, `sprintf`, `system`) is CWE-676, and one with no safe convention at all is CWE-242; `gets()` is on all three lists. A weak algorithm reached through a current API is CWE-327/CWE-328 instead.

## Key Principles

- Primary defence: replace the obsolete function with its current, maintained equivalent rather than adding checks around the old call
- Do not merely suppress or silence a deprecation warning without migrating the call
- Prioritize by risk: unbounded string/buffer functions (overflow), weak random number generators used for tokens or keys (predictability), and broken hash/cipher algorithms (collision or key recovery) are highest priority
- Search the codebase for every occurrence of the same function, not only the instance a scanner flagged
- Confirm the platform or language version's current deprecation list, since obsolete status and replacements can shift between releases
- Add a lint or static analysis rule preventing reintroduction of the retired function
- The distinction decides the work: an obsolete function has a named successor and the fix is a substitution, while a merely dangerous one is often correct where it stands and the fix is a judgement about this call site
- Prioritise withdrawn *security* helpers first - a removed TLS wrapper, password-hashing module, or credential API usually verified less than its replacement does, and there is no argument that makes it correct. A weak algorithm reached through a current API is CWE-327/CWE-328 instead

## Remediation Steps

- Locate - Find every call site of a function on the language or platform's obsolete/deprecated list
- Trace data flow - Determine what the function's output feeds: a buffer, a token, a digest, a file path, or a resource handle
- Identify the unsafe pattern - Unbounded operation, predictable output, a broken algorithm, or predict-then-create resource handling
- Replace with the safe pattern - Migrate to the bounded, cryptographically secure, or atomic equivalent for that operation
- Add secondary controls - A static analysis or linter rule that flags any future reintroduction of the obsolete function
- Test - Verify behavior at boundary conditions (empty and oversized input), confirm output format and length match expectations, and re-scan to confirm no remaining instances
