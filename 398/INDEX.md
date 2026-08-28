# CWE-398: Indicator of Poor Code Quality

## LLM Guidance

Poor code quality indicators - dead or unreachable code, empty or overly broad catch blocks, ignored return values, unused variables, and deeply nested or high-complexity logic - are not vulnerabilities on their own, but they mask and enable real security defects by making code harder to review, test, and reason about correctly. Treat a quality finding as a signal to do two things: fix the quality issue itself, and check whether it was hiding a more specific weakness such as missing validation, a swallowed error, or a resource leak. The remediation is disciplined code review, static analysis, and simplification rather than a single sink to patch.

## Key Principles

- Never silently swallow exceptions or errors; catch specific exception types and either handle them meaningfully or fail safely with clear logging
- Remove dead, unreachable, and commented-out code rather than leaving it in place; it can reintroduce risky behavior if reactivated and misleads reviewers about actual control flow
- Treat every ignored return value, unused variable, or unvalidated input near a flagged line as suspicious until confirmed harmless
- Prefer simple, linear control flow (early returns, small focused functions) over deep nesting so security-relevant logic stays auditable
- Integrate static analysis and linting into the normal build and review workflow so these indicators are caught early and consistently
- MITRE marks CWE-398 a Category and Prohibited for mapping, so a finding should carry a member weakness's number instead - but note the members are memory and API misuse (CWE-401, CWE-404, CWE-415, CWE-416, CWE-476, CWE-477), not the code smells scanners emit this ID for
- Where a more specific number exists for the smell it is usually outside this category: a result nobody inspects is CWE-252, a failure escaping the frame meant to contain it is CWE-248, an empty `catch` is CWE-390, and dead or irrelevant code is CWE-561/CWE-1164
- Where none of those fits, the honest answer is a maintainability defect with no CWE to carry it, and this entry is the remediation reference rather than a mapping target

## Remediation Steps

- Locate - Identify the flagged file, line, and specific quality issue (empty catch, dead code, unused variable, excessive complexity, missing validation)
- Assess security impact - Determine whether the issue itself creates risk directly (e.g., a swallowed exception hides an attack) or obscures a nearby defect
- Trace intent - Establish what the code is supposed to do, using surrounding logic or version history if intent is unclear
- Apply the specific fix - Handle exceptions explicitly by type, delete dead or unreachable code, remove unused variables (especially ones holding sensitive data), or decompose overly complex functions
- Check for masked defects - Re-review the surrounding logic for missing validation, missing resource cleanup, or missing authorization checks the quality issue may have concealed
- Add secondary controls - Run static analysis and linting as part of the build or review pipeline to catch recurrence
- Test - Confirm behavior is unchanged for valid inputs, exercise previously unreachable or ignored paths, and verify the static analysis finding clears
