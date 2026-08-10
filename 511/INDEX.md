# CWE-511: Logic/Time Bomb

## LLM Guidance

This weakness describes code that lies dormant until a date, event, execution count, or specific user condition triggers a destructive action, such as data deletion or service disruption. It typically appears as sabotage inserted by an insider or as a payload hidden inside a dependency. Remediation is centered on detection and removal: any conditional gate on a destructive operation that has no legitimate connection to the surrounding business logic should be treated as unauthorized and removed outright, not disabled or commented out.

## Key Principles

- Primary defence: remove any conditional trigger (hardcoded date, execution counter, specific username) gating a destructive action that lacks a documented business justification
- Do not disable suspicious code by commenting it out; remove it, since a disabled trigger can be silently re-enabled later
- Treat obfuscated code (encoded strings, dynamically evaluated conditions) as a red flag independent of what it turns out to do
- Where a time- or condition-based behavior is a legitimate feature, such as trial expiration, require it to be transparent, documented, code-reviewed, and driven by configuration rather than a hardcoded condition buried in unrelated logic
- Defence-in-depth: require independent code review for any change touching destructive operations, and log destructive operations with the acting user and call stack

## Remediation Steps

- Locate - Search for destructive operations (delete, drop, corrupt, shut down) and trace backward to any condition gating them
- Trace data flow - Determine what the condition depends on (date/time, counter, username, external flag) and whether that dependency relates to the code's stated purpose
- Identify the unsafe pattern - A conditional trigger unrelated to business logic, or obfuscated code hiding the condition from casual review
- Replace with the safe pattern - Remove the trigger entirely, or convert a legitimate conditional feature into transparent, configuration-driven, reviewed logic
- Add secondary controls - Static analysis rules flagging date comparisons or dynamic evaluation near destructive calls, mandatory multi-reviewer approval for such changes, and integrity checks on security-critical modules before execution
- Test - Run the code with the system clock advanced, with varied usernames, and under normal conditions to confirm no destructive action triggers unexpectedly
