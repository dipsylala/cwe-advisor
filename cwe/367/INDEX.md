# CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition

## LLM Guidance

A check and the use of what it established are two separate steps, with a window between them in which the state can change. Where there is no separate check - a plain unsynchronized read-modify-write - the entry is CWE-362, or CWE-366 where the racing parties are threads of one process.

## Key Principles

- Prefer APIs that combine check-and-act atomically (exclusive create flags, compare-and-swap, database row locks) over separate check-then-act calls
- Once a resource is checked, operate on the same handle or reference (file descriptor, locked row, object reference) rather than re-resolving it by name or ID later
- For filesystem paths, avoid a path-based check followed by a separate path-based operation, since the path can resolve to something different by the time of use
- For authorization, re-verify permissions at the point of the sensitive action itself, not only at request entry, since state can change during processing
- Hold any required lock continuously from the check through the use; releasing and reacquiring reopens the race window
- Treat any check whose result is used after more than a negligible delay as stale, and re-verify at the point of use
- Verify after opening, not before: once the file is open, `fstat(fd)` reports on the file that was actually opened, while `stat(path)` resolves the name again and can answer about a different one
- Prefer an API that does both at once - `open()` with `O_CREAT|O_EXCL` is an atomic check-and-create, where `if (exists) open()` is two steps with a window between them
- An in-process lock is enough only while the state is shared between threads of one process; across workers, replicas, or the filesystem it protects nothing

## Remediation Steps

- Locate - Find places where a condition is checked (existence, permission, balance, state) and a related action happens afterward
- Trace data flow - Measure the gap between check and use, and identify what else could run or change the checked resource in that window
- Identify the unsafe pattern - Separate check-then-act calls on a path, name, or value; a lock released between check and use; or a check performed early in a request but acted on later
- Replace with the safe pattern - Use an atomic check-and-act API, or retain and reuse the handle or lock obtained at check time through to the use
- Add secondary controls - Re-validate critical conditions such as authorization or balance immediately before the sensitive action as a final gate
- Test - Inject a concurrent modification between check and use (parallel threads or requests) and confirm the operation either blocks, fails safely, or remains correct
