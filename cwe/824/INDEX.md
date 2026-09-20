# CWE-824: Access of Uninitialized Pointer

## LLM Guidance

Record the finding here rather than against the Discouraged parents CWE-118 and CWE-119. Where the pointer is explicitly null rather than uninitialized - a failed lookup, an unchecked return - the weakness is CWE-476: the fix overlaps and the failure mode does not, since a null dereference faults predictably and this does not.

## Key Principles

- Initialize every pointer at declaration to either a valid address or an explicit null or empty sentinel; never leave it unset
- Initialize every pointer-typed struct or class field on every constructor path, including paths that exit early
- Check for a null or unset value immediately before dereferencing a pointer whose initialization is not guaranteed by the type system
- Fail loudly, returning an error or raising an exception, rather than continuing past an unchecked, possibly-uninitialized pointer
- Prefer language constructs that default pointer-like values to a safe empty state automatically over ones that leave them undefined
- Enable compiler warnings for uninitialized use as build failures, and use memory sanitizers during development as defence-in-depth
- The value in an uninitialized pointer is not random: it is whatever the program last left in that stack slot or heap cell, so it is repeatable for a given build and call sequence and shapeable by anyone who can influence the calls that ran earlier - which is what turns "reads garbage" into "writes to an address the attacker chose"

## Remediation Steps

- Locate - Identify pointer declarations and pointer-typed struct or class fields, and their first read or dereference
- Trace data flow - Follow each code path from declaration to first use, including branches, early returns, and exception paths, to find any path that skips assignment
- Identify the unsafe pattern - Look for a pointer declared without an initial value, or a constructor or branch that can exit before assigning it, followed by an unguarded dereference
- Replace with the safe pattern - Assign an explicit safe default at declaration and on every constructor path, and add a null check before any dereference not already guaranteed safe by the type system
- Add secondary controls - Enable compiler warnings for uninitialized use and treat them as build failures
- Test - Exercise every branch and early-exit path that could previously skip initialization, including exception paths, and confirm the pointer is never dereferenced in an unset state
