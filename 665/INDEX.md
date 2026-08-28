# CWE-665: Improper Initialization

## LLM Guidance

This weakness occurs when a variable, object field, buffer, or resource is read before it has been assigned a defined, safe value on every possible code path - an early return, an exception, or a partially run constructor can leave it unset. The uninitialized value may hold leftover memory, a permissive default, or unseeded cryptographic state, so behavior becomes dependent on unpredictable runtime conditions instead of explicit logic. The fix is to assign an explicit safe value at declaration or construction on every path, with security-relevant flags defaulting to deny.

## Key Principles

- Assign an explicit value at declaration or construction rather than leaving assignment to a later, conditional code path
- Security-relevant flags and permission state must default to the deny/false/unauthenticated state, never left unset
- Initialize pointers and references explicitly to null so a missed assignment fails fast rather than reading garbage
- Zero or otherwise define buffer contents on allocation rather than trusting the allocator to return clean memory
- Confirm cryptographic material (keys, IVs, seeds) is present and correctly generated before use, and fail loudly rather than proceeding with unset or zero values
- Use compiler warnings, static analysis, and memory sanitizers as a backstop to catch paths that skip initialization
- MITRE marks this Class Discouraged, so report the child: a missing variable initialization is CWE-456 and a use of one CWE-457, a handle, stream or connection is CWE-908/CWE-909, a value that *is* set and set wrongly is CWE-1419 or CWE-1188 (insecure default), and initialization that failed while the program carried on is CWE-455
- The dangerous shape is a security flag assigned only on the success path, so the failure path leaves it at whatever the declaration produced - where that is uninitialized memory the value is arbitrary and often non-zero, and the branch meaning "checked and valid" is entered on leftover data
- Initialize at the declaration and to the *safe* value (deny, false, empty), so a path that forgets to assign fails closed

## Remediation Steps

- Locate - identify a declaration, allocation, or constructor that does not assign a value on every path
- Trace data flow - find the first read of that value (a conditional check, buffer use, cryptographic operation, or return) and enumerate paths that reach it without assignment: an early branch, an exception, or partial construction
- Identify the unsafe pattern - a variable, field, or buffer left unset on at least one reachable path before use
- Replace with the safe pattern - assign a defined, safe value at declaration or on every constructor path, defaulting security flags to false/deny
- Add explicit fail-fast guards at security-sensitive sinks that reject an unset value rather than proceeding
- Add secondary controls - enable compiler and static-analysis warnings for uninitialized use and treat them as build failures
- Test - exercise every branch that could previously skip initialization, including error and exception paths, and confirm no path reads an unset value
