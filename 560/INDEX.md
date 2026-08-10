# CWE-560: Use of umask() with chmod-style Argument

## LLM Guidance

On Unix-family systems, `umask()` is subtractive: it removes permission bits from the process default (0666 for files, 0777 for directories) rather than setting the desired mode directly. Code that passes a `chmod`-style absolute value (for example 0600, intending "owner only") to `umask()` produces close to the opposite of what was intended, often leaving files world-writable. The fix is to pass the complement - the bits to remove - to `umask()`, or to set explicit permissions at file-creation time instead of relying on the ambient umask.

## Key Principles

- `umask()` answers "what to subtract from the default," not "what mode the file should end up with" - never pass it a value shaped like a chmod mode
- Prefer setting explicit permissions at file-creation time over relying on process-wide umask when the platform API supports it
- If the umask must be temporarily widened, save the prior value and restore it immediately afterward using a construct that guarantees restoration even on error
- Set a restrictive umask (0077 or 0027) once at process startup as the safe baseline
- Verify the actual resulting permissions after any umask change rather than trusting the passed value to be correct
- Remember umask is process-wide state - a change on one code path affects every file created afterward until it is reset

## Remediation Steps

- Locate - search for `umask()` calls and inspect the literal value passed
- Trace data flow - confirm the actual permission mode files or directories receive after the call, following every point where the umask is set or changed
- Identify the unsafe pattern - a value shaped like a chmod mode (0600, 0644, 0755) passed to `umask()`, or a temporary umask change that is never restored
- Replace with the safe pattern - compute the complement of the desired mode and pass that to `umask()`, or switch to an API that sets explicit permissions at creation time
- Restore the prior umask after any temporary change, using a construct that guarantees restoration even if creation fails
- Add secondary controls - set a restrictive process-wide umask baseline at startup independent of individual call sites
- Test - create a file after the fix and verify its actual permission bits match the intended mode exactly, and check for stray world-writable files
