# CWE-691: Insufficient Control Flow Management

## LLM Guidance

Insufficient control flow management occurs when code proceeds past a security-relevant operation without checking its outcome, or allows a state transition that should not be legal from the current state. Attackers exploit this by forcing an ignored failure, sending unexpected input, or racing a state change to reach code that should have been unreachable. The core fix is to make every security-relevant outcome an explicit branch point and to enforce valid state transitions rather than assuming the intended path was followed.

## Key Principles

- Treat the return value, exception, or status of every security-relevant operation as mandatory to check before continuing
- Never assume a downstream step succeeded because an earlier operation was attempted; verify it explicitly
- Model objects with meaningful states, such as authentication or workflow stages, as explicit state machines that reject illegal transitions
- Fail closed on an unexpected, null, or error result: stop and deny rather than proceeding on a default assumption
- Use guard clauses that reject invalid conditions early rather than nesting the valid path inside layered conditionals
- Re-validate preconditions at every entry point that reaches sensitive code, not only at the start of a workflow

## Remediation Steps

- Locate - Identify each security-relevant operation (authentication, authorization, payment or inventory check, cryptographic verification, resource acquisition) and the code that runs immediately after it
- Trace data flow - Follow the operation's return value, exception, or status to the call site and confirm whether it is inspected before the next step executes
- Identify the unsafe pattern - Look for unchecked return values, swallowed exceptions, fall-through error handling, or state changes applied without validating the current state
- Replace with the safe pattern - Add an explicit check-then-branch after every security-relevant call, and require state transitions to validate the current state before applying
- Add secondary controls - Log rejected transitions and failed checks, and default to denying access when a check result is inconclusive
- Test - Force each checked operation to fail and confirm execution halts instead of continuing; attempt state transitions out of order and confirm each is rejected
